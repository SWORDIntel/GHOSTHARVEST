import asyncio
import os
import logging
import re
import docx # type: ignore
import fitz  # PyMuPDF
from typing import Optional

# Assuming src.utils and src.config exist and are importable
# These will be replaced by actual imports if running in a full environment.
try:
    from src import utils
    from src import config
except ImportError:
    # Mock objects for utils and config for standalone testing or linting
    class MockUtils:
        async def write_file_async(self, path: str, content: str, encoding: str = "utf-8") -> bool:
            try:
                with open(path, "w", encoding=encoding) as f:
                    f.write(content)
                logging.info(f"MockUtils: Successfully wrote to {path}")
                return True
            except Exception as e:
                logging.error(f"MockUtils: Error writing to {path}: {e}")
                return False

        async def read_file_async(self, path: str, encoding: str = "utf-8") -> Optional[str]:
            try:
                with open(path, "r", encoding=encoding) as f:
                    content = f.read()
                logging.info(f"MockUtils: Successfully read from {path}")
                return content
            except Exception as e:
                logging.error(f"MockUtils: Error reading from {path}: {e}")
                return None

    utils = MockUtils()

    class MockConfig:
        pass # Add any necessary config attributes if text_converter directly uses them
    config = MockConfig()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def normalize_whitespace(text: str) -> str:
    """
    Aggressively normalizes whitespace.
    - Replaces multiple spaces/tabs with a single space.
    - Replaces multiple newlines with a single newline.
    - Strips leading/trailing whitespace.
    """
    text = re.sub(r'[ \t]+', ' ', text)  # Replace multiple spaces/tabs with a single space
    text = re.sub(r'\n+', '\n', text)    # Replace multiple newlines with a single newline
    return text.strip()

async def _extract_text_from_docx(file_path: str) -> Optional[str]:
    """Helper function to extract text from DOCX using python-docx."""
    try:
        loop = asyncio.get_event_loop()
        doc = await loop.run_in_executor(None, docx.Document, file_path)
        full_text = []
        for para in doc.paragraphs:
            full_text.append(para.text)
        # Note: This does not extract text from tables, headers, footers, etc.
        # For a more comprehensive extraction, one would need to iterate
        # through table cells, sections, etc. The current subtask asks for "raw text".
        return "\n".join(full_text)
    except Exception as e:
        logging.error(f"Error extracting text from DOCX {file_path}: {e}")
        return None

async def _extract_text_from_pdf(file_path: str, output_path: str) -> Optional[str]:
    """
    Helper function to extract text from PDF using PyMuPDF (fitz).
    Checks if PDF is text-selectable. If not, deletes the PDF and returns None.
    """
    try:
        doc = fitz.open(file_path)
        is_text_selectable = False
        total_text_len = 0
        for page_num in range(len(doc)):
            page = doc.load_page(page_num)
            # Attempt to extract a small amount of text to check selectability
            text_on_page = page.get_text("text", sort=True) # sort=True for reading order
            total_text_len += len(text_on_page.strip())
            if len(text_on_page.strip()) > 0 : # Heuristic: if any page has some text
                is_text_selectable = True
                # No need to check all pages if one is found to be selectable with substantial text
                # break # Or continue to get all text below

        if not is_text_selectable or total_text_len < 10: # Heuristic for very short/no text
            logging.warning(
                f"PDF {file_path} does not appear to contain selectable text (scanned or image-based) "
                f"or contains very little text (length: {total_text_len}). Discarding file."
            )
            doc.close()
            try:
                os.remove(file_path)
                logging.info(f"Successfully deleted non-selectable PDF: {file_path}")
            except OSError as e_remove:
                logging.error(f"Error deleting non-selectable PDF {file_path}: {e_remove}")
            return None

        # If selectable, extract all text
        full_text = []
        for page_num in range(len(doc)):
            page = doc.load_page(page_num)
            full_text.append(page.get_text("text", sort=True)) # Extract text in reading order
        doc.close()
        return "\n".join(full_text)
    except Exception as e:
        logging.error(f"Error processing PDF {file_path}: {e}")
        if 'doc' in locals() and doc: # Ensure document is closed if opened
            doc.close()
        return None


async def convert_to_minimized_txt(file_path: str, output_path: str) -> bool:
    """
    Converts a given file (.docx, .pdf, .txt) to a minimized plain text file.

    Args:
        file_path: Path to the input file.
        output_path: Path to save the converted text file.

    Returns:
        True if conversion was successful and file was saved, False otherwise.
    """
    if not os.path.exists(file_path):
        logging.error(f"Input file not found: {file_path}")
        return False

    _, extension = os.path.splitext(file_path)
    extension = extension.lower()
    raw_text: Optional[str] = None

    logging.info(f"Starting conversion for {file_path} to {output_path}")

    try:
        if extension == ".docx":
            raw_text = await _extract_text_from_docx(file_path)
        elif extension == ".pdf":
            raw_text = await _extract_text_from_pdf(file_path, output_path) # output_path not used by current _extract_text_from_pdf
            if raw_text is None: # PDF was non-selectable and deleted
                return False
        elif extension == ".txt":
            raw_text = await utils.read_file_async(file_path)
        else:
            logging.warning(f"Unsupported file type: {extension} for file {file_path}. Skipping.")
            return False

        if raw_text is None:
            # This case handles errors from _extract_text_from_docx or read_file_async for .txt
            logging.error(f"Failed to extract raw text from {file_path}.")
            return False

        minimized_text = normalize_whitespace(raw_text)

        if not minimized_text:
            logging.warning(f"No text content found after normalization in {file_path}. Output file will be empty.")
            # Still proceed to write an empty file as per "Save to output_path"

        success = await utils.write_file_async(output_path, minimized_text, encoding="utf-8")
        if success:
            logging.info(f"Successfully converted and saved {file_path} to {output_path}")
            return True
        else:
            logging.error(f"Failed to write minimized text to {output_path} for file {file_path}")
            return False

    except Exception as e:
        logging.error(f"An unexpected error occurred during conversion of {file_path}: {e}")
        return False

if __name__ == '__main__':
    # Example Usage (requires actual files and dependencies)
    # Create dummy files for testing if needed
    async def main_test():
        # Create a dummy utils and config if not present (e.g. for direct script run)
        # This is already handled by the try-except ImportError at the top for module-level mocks

        # Test DOCX
        # You would need to create a dummy .docx file named 'test.docx'
        # For example, create one with Word and put some text in it.
        if not os.path.exists("test.docx"):
             print("Skipping DOCX test, test.docx not found.")
        else:
            print("\nTesting DOCX conversion...")
            success_docx = await convert_to_minimized_txt("test.docx", "test_output.docx.txt")
            print(f"DOCX conversion successful: {success_docx}")
            if success_docx:
                # You can check 'test_output.docx.txt'
                pass

        # Test PDF (selectable)
        # You would need a selectable PDF named 'test_selectable.pdf'
        # To create one: print any document to PDF.
        if not os.path.exists("test_selectable.pdf"):
            print("Skipping Selectable PDF test, test_selectable.pdf not found.")
        else:
            print("\nTesting Selectable PDF conversion...")
            success_pdf_sel = await convert_to_minimized_txt("test_selectable.pdf", "test_output.pdf.txt")
            print(f"Selectable PDF conversion successful: {success_pdf_sel}")
            if success_pdf_sel:
                # You can check 'test_output.pdf.txt'
                pass

        # Test PDF (scanned/image-based) - This should delete the file
        # You would need a scanned PDF named 'test_scanned.pdf'
        # To create one: scan a document or take a picture and save as PDF.
        # Ensure it's actually image-based.
        scanned_pdf_path = "test_scanned.pdf"
        if not os.path.exists(scanned_pdf_path):
            print(f"Skipping Scanned PDF test, {scanned_pdf_path} not found.")
        else:
            print(f"\nTesting Scanned PDF (will attempt to delete {scanned_pdf_path})...")
            # Create a copy to avoid deleting the original if you want to keep it for re-testing
            # import shutil
            # shutil.copy(scanned_pdf_path, "test_scanned_copy.pdf")
            # success_pdf_scan = await convert_to_minimized_txt("test_scanned_copy.pdf", "test_output_scanned.pdf.txt")
            success_pdf_scan = await convert_to_minimized_txt(scanned_pdf_path, "test_output_scanned.pdf.txt")
            print(f"Scanned PDF handling (should be False, file deleted): {success_pdf_scan}")
            if not success_pdf_scan and not os.path.exists(scanned_pdf_path): # or "test_scanned_copy.pdf"
                print(f"{scanned_pdf_path} (or its copy) was deleted as expected.")
            elif os.path.exists(scanned_pdf_path): # or "test_scanned_copy.pdf"
                 print(f"WARNING: {scanned_pdf_path} (or its copy) was NOT deleted.")


        # Test TXT
        # Create a dummy .txt file
        if not os.path.exists("test.txt"):
            with open("test.txt", "w") as f:
                f.write("This   is a test.\n\nWith multiple   spaces and\n\n\nnewlines.")
            print("Created dummy test.txt for testing.")

        print("\nTesting TXT conversion...")
        success_txt = await convert_to_minimized_txt("test.txt", "test_output.txt.txt")
        print(f"TXT conversion successful: {success_txt}")
        if success_txt:
            # You can check 'test_output.txt.txt'
            pass

        # Test unsupported file
        if not os.path.exists("test.unsupported"):
            with open("test.unsupported", "w") as f:
                f.write("Dummy content")
        print("\nTesting unsupported file type...")
        success_unsupported = await convert_to_minimized_txt("test.unsupported", "test_output.unsupported.txt")
        print(f"Unsupported file conversion (should be False): {success_unsupported}")


    if __name__ == '__main__':
        asyncio.run(main_test())
