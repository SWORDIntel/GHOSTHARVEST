import asyncio
import os
import zipfile # Used for mocking, not actual zip operations in test code
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call, mock_open # Added mock_open

# Modules to be tested or mocked
from src.targets import gutenberg # The module under test
# Assuming BaseTarget is importable for type checks if needed, but not strictly for these tests
# from src.targets.base_target import BaseTarget

# Sample RDF content as a string
SAMPLE_RDF_CONTENT = """
<rdf:RDF xmlns:dcterms="http://purl.org/dc/terms/" xmlns:pgterms="http://www.gutenberg.org/2009/pgterms/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <pgterms:ebook rdf:about="ebooks/1">
    <dcterms:title>Book Title 1 (Psychology)</dcterms:title>
    <dcterms:subject><rdf:Description><rdf:value>Psychology</rdf:value></rdf:Description></dcterms:subject>
    <dcterms:hasFormat>
      <pgterms:file rdf:about="http://www.gutenberg.org/files/1/1-0.txt">
        <dcterms:format><rdf:Description><rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">text/plain; charset=utf-8</rdf:value></rdf:Description></dcterms:format>
      </pgterms:file>
    </dcterms:hasFormat>
    <dcterms:hasFormat>
      <pgterms:file rdf:about="http://www.gutenberg.org/ebooks/1.epub.images">
        <dcterms:format><rdf:Description><rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">application/epub+zip</rdf:value></rdf:Description></dcterms:format>
      </pgterms:file>
    </dcterms:hasFormat>
  </pgterms:ebook>
  <pgterms:ebook rdf:about="ebooks/2">
    <dcterms:title>Book Title 2 (History)</dcterms:title>
    <dcterms:subject><rdf:Description><rdf:value>History</rdf:value></rdf:Description></dcterms:subject>
    <dcterms:hasFormat>
      <pgterms:file rdf:about="https://www.gutenberg.org/ebooks/2.txt.utf-8">
        <dcterms:format><rdf:Description><rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">text/plain; charset=utf-8</rdf:value></rdf:Description></dcterms:format>
      </pgterms:file>
    </dcterms:hasFormat>
  </pgterms:ebook>
  <pgterms:ebook rdf:about="ebooks/3">
    <dcterms:title>Another Psychology Book</dcterms:title>
    <dcterms:subject><rdf:Description><rdf:value>Applied Psychology</rdf:value></rdf:Description></dcterms:subject>
    <dcterms:hasFormat>
      <pgterms:file rdf:about="https://www.gutenberg.org/cache/epub/3/pg3.txt">
        <dcterms:format><rdf:Description><rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">text/plain</rdf:value></rdf:Description></dcterms:format>
      </pgterms:file>
    </dcterms:hasFormat>
  </pgterms:ebook>
  <pgterms:ebook rdf:about="ebooks/4">
    <dcterms:title>No Text Link Book</dcterms:title>
    <dcterms:hasFormat>
      <pgterms:file rdf:about="http://www.gutenberg.org/ebooks/4.epub.images">
        <dcterms:format><rdf:Description><rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">application/epub+zip</rdf:value></rdf:Description></dcterms:format>
      </pgterms:file>
    </dcterms:hasFormat>
  </pgterms:ebook>
</rdf:RDF>
"""

# Define default mock config values relevant to GutenbergTarget
DEFAULT_MOCK_CONFIG_VALUES = {
    "CATALOG_URL": "http://fakecatalog.com/catalog.rdf.zip",
    "TEMP_DIR": "/tmp/gh_test_temp_gutenberg"
}

class TestGutenbergTarget(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        logging.disable(logging.CRITICAL) # Suppress logs during tests

        self.mock_config = MagicMock()
        for key, value in DEFAULT_MOCK_CONFIG_VALUES.items():
            setattr(self.mock_config, key, value)

        # Patch external dependencies for GutenbergTarget
        # Note: Patching 'src.targets.gutenberg.config' and 'src.targets.gutenberg.utils'
        self.patchers = {
            'config': patch('src.targets.gutenberg.config', self.mock_config),
            'utils': patch('src.targets.gutenberg.utils', MagicMock()), # For get_random_user_agent
            'aiohttp_session': patch('src.targets.gutenberg.aiohttp.ClientSession', new_callable=MagicMock),
            'aiofiles_open': patch('src.targets.gutenberg.aiofiles.open', new_callable=mock_open), # General mock for aiofiles
            'os_remove': patch('src.targets.gutenberg.os.remove'),
            'os_makedirs': patch('src.targets.gutenberg.os.makedirs'),
            'zipfile_ZipFile': patch('src.targets.gutenberg.zipfile.ZipFile'), # For _extract_zip_member
            # Patch the executor directly if _extract_zip_member is simple or patch _extract_zip_member itself
            '_extract_zip_member_patch': patch.object(gutenberg.GutenbergTarget, '_extract_zip_member', new_callable=MagicMock)
        }
        self.mocks = {name: patcher.start() for name, patcher in self.patchers.items()}

        # Configure specific mock behaviors
        self.mocks['utils'].get_random_user_agent.return_value = "TestUserAgent/Gutenberg/1.0"

        # Mock for aiohttp.ClientSession().get().__aenter__().read()
        self.mock_aiohttp_response = AsyncMock()
        self.mock_aiohttp_response.content.read = AsyncMock(return_value=b"") # Default empty chunk
        self.mock_aiohttp_response.raise_for_status = MagicMock()

        mock_session_instance = self.mocks['aiohttp_session'].return_value
        mock_session_instance.__aenter__.return_value.get.return_value.__aenter__.return_value = self.mock_aiohttp_response

        # Default for _extract_zip_member: successfully "extracts" and returns a path
        self.rdf_file_path_in_temp = os.path.join(self.mock_config.TEMP_DIR, "catalog.rdf")
        self.mocks['_extract_zip_member_patch'].return_value = self.rdf_file_path_in_temp

        # Default for aiofiles.open to provide RDF content when reading the "extracted" rdf file
        self.mock_aiofiles_open_instance = self.mocks['aiofiles_open'].return_value
        self.mock_aiofiles_open_instance.__aenter__.return_value.read = AsyncMock(return_value=SAMPLE_RDF_CONTENT)

    async def asyncTearDown(self):
        logging.disable(logging.NOTSET)
        for patcher in self.patchers.values():
            patcher.stop()

    async def test_get_target_name(self):
        target = gutenberg.GutenbergTarget()
        self.assertEqual(await target.get_target_name(), "project_gutenberg")

    # --- Tests for discover_links ---

    async def test_discover_links_successful_discovery_no_filters(self):
        target = gutenberg.GutenbergTarget()

        # Mock _download_catalog to return True (simulating successful download)
        # This is implicitly done by mocking aiohttp and aiofiles.open for writing the zip
        # We can also directly mock the _download_catalog helper
        with patch.object(target, '_download_catalog', AsyncMock(return_value=True)) as mock_download_helper:
            links = await target.discover_links(downloaded_urls=set(), keyword_filters=None)

        mock_download_helper.assert_called_once()
        self.mocks['_extract_zip_member_patch'].assert_called_once()
        self.mocks['aiofiles_open'].assert_any_call(self.rdf_file_path_in_temp, 'r', encoding='utf-8') # Reading RDF

        expected_links = {
            "http://www.gutenberg.org/files/1/1-0.txt",      # Normalized to https later in code
            "https://www.gutenberg.org/ebooks/2.txt.utf-8",
            "https://www.gutenberg.org/cache/epub/3/pg3.txt"
        }
        # Normalize HTTP to HTTPS for comparison as the code does this
        normalized_links_from_code = {link.replace("http://", "https://") if link.startswith("http://") else link for link in links}

        self.assertCountEqual(normalized_links_from_code, expected_links)
        # Check cleanup calls
        self.mocks['os_remove'].assert_any_call(os.path.join(self.mock_config.TEMP_DIR, "catalog.rdf.zip"))
        self.mocks['os_remove'].assert_any_call(self.rdf_file_path_in_temp)


    async def test_discover_links_with_keyword_filtering(self):
        target = gutenberg.GutenbergTarget()
        with patch.object(target, '_download_catalog', AsyncMock(return_value=True)):
            links = await target.discover_links(downloaded_urls=set(), keyword_filters=["psychology"])

        expected_links = {
            "http://www.gutenberg.org/files/1/1-0.txt", # Book 1: "Psychology"
            "https://www.gutenberg.org/cache/epub/3/pg3.txt"  # Book 3: "Another Psychology Book"
        }
        normalized_links_from_code = {link.replace("http://", "https://") if link.startswith("http://") else link for link in links}
        self.assertCountEqual(normalized_links_from_code, expected_links)

    async def test_discover_links_with_keyword_filtering_case_insensitive(self):
        target = gutenberg.GutenbergTarget()
        with patch.object(target, '_download_catalog', AsyncMock(return_value=True)):
             # Keyword is "HISTORY", sample data has "History"
            links = await target.discover_links(downloaded_urls=set(), keyword_filters=["HISTORY"])

        expected_links = {
            "https://www.gutenberg.org/ebooks/2.txt.utf-8" # Book 2: "History"
        }
        self.assertCountEqual(set(links), expected_links)


    async def test_discover_links_filtering_already_downloaded(self):
        target = gutenberg.GutenbergTarget()
        downloaded_urls_set = {"https://www.gutenberg.org/ebooks/2.txt.utf-8"} # Book 2 is "downloaded"

        with patch.object(target, '_download_catalog', AsyncMock(return_value=True)):
            links = await target.discover_links(downloaded_urls=downloaded_urls_set, keyword_filters=None)

        expected_links_after_filtering = {
            "http://www.gutenberg.org/files/1/1-0.txt",
            "https://www.gutenberg.org/cache/epub/3/pg3.txt"
        }
        normalized_links_from_code = {link.replace("http://", "https://") if link.startswith("http://") else link for link in links}
        self.assertCountEqual(normalized_links_from_code, expected_links_after_filtering)


    async def test_discover_links_catalog_download_fails(self):
        target = gutenberg.GutenbergTarget()
        # Mock the _download_catalog helper to simulate failure
        with patch.object(target, '_download_catalog', AsyncMock(return_value=False)) as mock_download_helper:
            with patch('src.targets.gutenberg.logging.error') as mock_logging_error: # Check specific log
                links = await target.discover_links(set())

        self.assertEqual(links, [])
        mock_download_helper.assert_called_once()
        # mock_logging_error.assert_any_call("Error downloading catalog") # This log is inside _download_catalog
        # If _download_catalog returns False, discover_links itself doesn't log another error, just returns [].


    async def test_discover_links_zip_decompression_fails(self):
        target = gutenberg.GutenbergTarget()
        self.mocks['_extract_zip_member_patch'].return_value = None # Simulate extraction failure

        with patch.object(target, '_download_catalog', AsyncMock(return_value=True)): # Download succeeds
            with patch('src.targets.gutenberg.logging.error') as mock_logging_error:
                links = await target.discover_links(set())

        self.assertEqual(links, [])
        mock_logging_error.assert_any_call("Failed to extract catalog.rdf from the zip.")


    async def test_discover_links_rdf_parsing_fails(self):
        target = gutenberg.GutenbergTarget()
        # Simulate RDF content that is invalid XML
        self.mock_aiofiles_open_instance.__aenter__.return_value.read = AsyncMock(return_value="<rdf:RDF><unterminated>")

        with patch.object(target, '_download_catalog', AsyncMock(return_value=True)): # Download and extract succeed
             with patch('src.targets.gutenberg.logging.error') as mock_logging_error:
                links = await target.discover_links(set())

        self.assertEqual(links, [])
        self.assertTrue(any("Error parsing RDF XML" in args[0] for args, kwargs in mock_logging_error.call_args_list))

    async def test_discover_links_empty_rdf_content(self):
        target = gutenberg.GutenbergTarget()
        self.mock_aiofiles_open_instance.__aenter__.return_value.read = AsyncMock(return_value=" ") # Empty or whitespace only

        with patch.object(target, '_download_catalog', AsyncMock(return_value=True)):
            with patch('src.targets.gutenberg.logging.warning') as mock_logging_warning: # Should be a warning
                links = await target.discover_links(set())

        self.assertEqual(links, [])
        mock_logging_warning.assert_any_call("RDF content is empty. Cannot parse.")


if __name__ == '__main__':
    unittest.main()
