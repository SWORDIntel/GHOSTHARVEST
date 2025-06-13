import asyncio
import os
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call # Added call

# Modules to be tested or mocked
from src import text_converter # This is the module we are testing

# Path to the sample .txt file (assuming tests are run from ghost_harvester_v1.1 directory or configured path)
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), 'samples')
SAMPLE_TXT_PATH = os.path.join(SAMPLES_DIR, 'sample.txt')


class TestTextConverter(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Suppress logging output during tests unless specifically testing for it
        logging.disable(logging.CRITICAL)
        # Ensure the samples directory exists if sample.txt is to be read by some tests
        # (though sample.txt creation is handled by a previous step in the overall plan)
        os.makedirs(SAMPLES_DIR, exist_ok=True)


    def tearDown(self):
        # Re-enable logging
        logging.disable(logging.NOTSET)

    # --- Test DOCX Conversion ---
    @patch('src.text_converter.docx.Document') # Mock the Document class from the docx library
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock)
    @patch('src.text_converter.logging')
    async def test_docx_conversion_success(self, mock_logging, mock_write_file_async, mock_docx_document):
        # Prepare mock for docx.Document
        mock_doc_instance = MagicMock()
        mock_para1 = MagicMock()
        mock_para1.text = "Hello World.  Extra   spaces."
        mock_para2 = MagicMock()
        mock_para2.text = "New line."
        mock_doc_instance.paragraphs = [mock_para1, mock_para2]
        mock_docx_document.return_value = mock_doc_instance

        mock_write_file_async.return_value = True # Simulate successful write

        input_path = "dummy_sample.docx"
        output_path = "dummy_output.txt"

        result = await text_converter.convert_to_minimized_txt(input_path, output_path)

        self.assertTrue(result)
        mock_docx_document.assert_called_once_with(input_path)
        # Expected text after joining paragraphs with \n and then normalizing whitespace
        expected_text = "Hello World. Extra spaces.\nNew line."
        mock_write_file_async.assert_called_once_with(output_path, expected_text, encoding="utf-8")

    # --- Test Born-Digital PDF Conversion ---
    @patch('src.text_converter.fitz.open') # Mock fitz.open
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock)
    @patch('src.text_converter.logging')
    async def test_pdf_digital_conversion_success(self, mock_logging, mock_write_file_async, mock_fitz_open):
        # Prepare mock for fitz.open() -> Document -> Page -> get_text()
        mock_pdf_doc = MagicMock()
        mock_page1 = MagicMock()
        mock_page1.get_text.return_value = "This is a digital PDF. 	Tab here."
        mock_page2 = MagicMock()
        mock_page2.get_text.return_value = "Multiple  spaces."

        # Simulate document having two pages
        mock_pdf_doc.__len__.return_value = 2
        mock_pdf_doc.load_page.side_effect = [mock_page1, mock_page2]
        mock_pdf_doc.close = MagicMock() # Ensure close can be called

        mock_fitz_open.return_value = mock_pdf_doc
        mock_write_file_async.return_value = True

        input_path = "dummy_digital.pdf"
        output_path = "dummy_output.pdf.txt"

        result = await text_converter.convert_to_minimized_txt(input_path, output_path)

        self.assertTrue(result)
        mock_fitz_open.assert_called_once_with(input_path)
        mock_page1.get_text.assert_called_with("text", sort=True)
        mock_page2.get_text.assert_called_with("text", sort=True)
        # Expected text after joining page texts with \n and then normalizing
        expected_text = "This is a digital PDF. Tab here.\nMultiple spaces."
        mock_write_file_async.assert_called_once_with(output_path, expected_text, encoding="utf-8")
        mock_pdf_doc.close.assert_called_once()


    # --- Test Scanned/Image-PDF Discard Logic ---
    @patch('src.text_converter.fitz.open')
    @patch('src.text_converter.os.remove')
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock) # Should not be called
    @patch('src.text_converter.logging')
    async def test_pdf_scanned_discarded(self, mock_logging, mock_write_file_async, mock_os_remove, mock_fitz_open):
        mock_pdf_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_text.return_value = "  " # Empty or only whitespace, or very short text

        mock_pdf_doc.__len__.return_value = 1
        mock_pdf_doc.load_page.return_value = mock_page
        mock_pdf_doc.close = MagicMock()
        mock_fitz_open.return_value = mock_pdf_doc

        input_path = "dummy_scanned.pdf"
        output_path = "dummy_scanned_output.txt"

        result = await text_converter.convert_to_minimized_txt(input_path, output_path)

        self.assertFalse(result)
        mock_fitz_open.assert_called_once_with(input_path)
        mock_os_remove.assert_called_once_with(input_path)
        mock_write_file_async.assert_not_called()
        # Check for a specific part of the warning message
        self.assertTrue(any("does not appear to contain selectable text" in args[0] for args, kwargs in mock_logging.warning.call_args_list))
        mock_pdf_doc.close.assert_called_once()

    # --- Test TXT Conversion ---
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock)
    @patch('src.text_converter.utils.read_file_async', new_callable=AsyncMock) # Mock read_file_async for consistency
    @patch('src.text_converter.logging')
    async def test_txt_conversion_success(self, mock_logging, mock_read_file_async, mock_write_file_async):
        # Content from the sample.txt file created earlier
        original_text = "Plain text file with   multiple spaces and\n\nmultiple newlines."
        mock_read_file_async.return_value = original_text # Simulate reading the file
        mock_write_file_async.return_value = True

        input_path = SAMPLE_TXT_PATH # Using the actual path for this one, but read is mocked
        output_path = "dummy_output.txt.txt"

        result = await text_converter.convert_to_minimized_txt(input_path, output_path)

        self.assertTrue(result)
        mock_read_file_async.assert_called_once_with(input_path)
        expected_text = "Plain text file with multiple spaces and\nmultiple newlines."
        mock_write_file_async.assert_called_once_with(output_path, expected_text, encoding="utf-8")

    # --- Test Unsupported File Type ---
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock) # Should not be called
    @patch('src.text_converter.logging')
    async def test_unsupported_file_type(self, mock_logging, mock_write_file_async):
        input_path = "unsupported.png"
        output_path = "dummy_output.png.txt"

        result = await text_converter.convert_to_minimized_txt(input_path, output_path)

        self.assertFalse(result)
        mock_write_file_async.assert_not_called()
        self.assertTrue(any(f"Unsupported file type: .png for file {input_path}" in args[0] for args, kwargs in mock_logging.warning.call_args_list))

    # --- Test File Not Found ---
    @patch('src.text_converter.docx.Document') # Mock at the point of use for .docx
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock) # Should not be called
    @patch('src.text_converter.logging')
    async def test_file_not_found_docx(self, mock_logging, mock_write_file_async, mock_docx_document):
        input_path = "nonexistent.docx"
        output_path = "dummy_output_nonexistent.txt"

        # Mock os.path.exists to return False to hit the initial check
        with patch('src.text_converter.os.path.exists', return_value=False) as mock_exists:
            result = await text_converter.convert_to_minimized_txt(input_path, output_path)
            mock_exists.assert_called_once_with(input_path)

        self.assertFalse(result)
        mock_docx_document.assert_not_called() # Should not even try to open if path check fails
        mock_write_file_async.assert_not_called()
        mock_logging.error.assert_any_call(f"Input file not found: {input_path}")

    @patch('src.text_converter.fitz.open') # Mock at the point of use for .pdf
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock) # Should not be called
    @patch('src.text_converter.logging')
    async def test_file_not_found_pdf(self, mock_logging, mock_write_file_async, mock_fitz_open):
        input_path = "nonexistent.pdf"
        output_path = "dummy_output_nonexistent.pdf.txt"

        with patch('src.text_converter.os.path.exists', return_value=False) as mock_exists:
            result = await text_converter.convert_to_minimized_txt(input_path, output_path)
            mock_exists.assert_called_once_with(input_path)

        self.assertFalse(result)
        mock_fitz_open.assert_not_called()
        mock_write_file_async.assert_not_called()
        mock_logging.error.assert_any_call(f"Input file not found: {input_path}")


    @patch('src.text_converter.utils.read_file_async', new_callable=AsyncMock) # Mock for .txt
    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock) # Should not be called
    @patch('src.text_converter.logging')
    async def test_file_not_found_txt(self, mock_logging, mock_write_file_async, mock_read_file_async):
        input_path = "nonexistent.txt"
        output_path = "dummy_output_nonexistent.txt.txt"

        # Simulate file not found at the os.path.exists level
        with patch('src.text_converter.os.path.exists', return_value=False) as mock_exists:
            result = await text_converter.convert_to_minimized_txt(input_path, output_path)
            mock_exists.assert_called_once_with(input_path)

        self.assertFalse(result)
        mock_read_file_async.assert_not_called() # Should not try to read if path check fails
        mock_write_file_async.assert_not_called()
        mock_logging.error.assert_any_call(f"Input file not found: {input_path}")

    @patch('src.text_converter.utils.write_file_async', new_callable=AsyncMock)
    @patch('src.text_converter.logging')
    async def test_empty_input_file_docx(self, mock_logging, mock_write_file_async):
        # Test if DOCX is empty, results in empty output but still True
        with patch('src.text_converter.docx.Document') as mock_docx_document:
            mock_doc_instance = MagicMock()
            mock_doc_instance.paragraphs = [] # No paragraphs
            mock_docx_document.return_value = mock_doc_instance
            mock_write_file_async.return_value = True

            result = await text_converter.convert_to_minimized_txt("empty.docx", "output.txt")
            self.assertTrue(result)
            mock_write_file_async.assert_called_once_with("output.txt", "", encoding="utf-8")
            mock_logging.warning.assert_any_call("No text content found after normalization in empty.docx. Output file will be empty.")


if __name__ == '__main__':
    unittest.main()
