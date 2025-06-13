import asyncio
import os
import zipfile
import logging
from typing import Set, List, Optional, Dict, Any
import aiohttp
import aiofiles
from lxml import etree # type: ignore

try:
    from src.targets.base_target import BaseTarget
    from src import utils
    from src import config
except ImportError:
    logging.warning("Using mock objects for BaseTarget, src.utils, src.config for gutenberg.py.")
    # Mock BaseTarget if not found (e.g. running script directly)
    class BaseTarget: # type: ignore
        async def get_target_name(self) -> str: raise NotImplementedError
        async def discover_links(self, downloaded_urls: Set[str], keyword_filters: Optional[List[str]] = None) -> List[str]: raise NotImplementedError

    class MockUtils:
        async def read_file_async(self, path: str, encoding: str = "utf-8") -> Optional[str]:
            async with aiofiles.open(path, "r", encoding=encoding) as f: return await f.read()
        def get_random_user_agent(self) -> str: return "MockedAgent/1.0"
        # Add other utils methods if GutenbergTarget ends up using them

    class MockConfig:
        CATALOG_URL = "https_bad_url_for_testing_only_no_protocol_www.gutenberg.org/cache/epub/catalog.rdf.zip" # Ensure this is a valid URL for testing
        TEMP_DIR = "temp_gutenberg"
        # Add other config values if needed

    utils = MockUtils()
    config = MockConfig()
    os.makedirs(config.TEMP_DIR, exist_ok=True)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common RDF namespaces for Project Gutenberg
NAMESPACES = {
    'rdf': "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    'dcterms': "http://purl.org/dc/terms/",
    'pgterms': "http://www.gutenberg.org/2009/pgterms/"
}

class GutenbergTarget(BaseTarget):
    """
    Target implementation for Project Gutenberg.
    Downloads and parses the catalog.rdf.zip to discover .txt file links.
    """

    async def get_target_name(self) -> str:
        return "project_gutenberg"

    def _extract_zip_member(self, zip_file_path: str, member_name: str, dest_path: str) -> Optional[str]:
        """Synchronous helper to extract a single member from a zip file."""
        try:
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                # Ensure member_name is just the filename, not a path
                member_filename = os.path.basename(member_name)
                # Find the member in the zip file (case-insensitive if needed, but usually exact)
                actual_member = next((m for m in zip_ref.namelist() if m.endswith(member_filename)), None)
                if not actual_member:
                    logging.error(f"Member '{member_filename}' not found in '{zip_file_path}'. Available: {zip_ref.namelist()}")
                    return None

                extracted_path = zip_ref.extract(actual_member, dest_path)
                logging.info(f"Extracted '{actual_member}' to '{extracted_path}'")
                return extracted_path
        except zipfile.BadZipFile:
            logging.error(f"Bad zip file: {zip_file_path}")
            return None
        except Exception as e:
            logging.error(f"Error extracting '{member_name}' from '{zip_file_path}': {e}")
            return None

    async def _download_catalog(self, temp_zip_path: str) -> bool:
        """Downloads the catalog file."""
        logging.info(f"Downloading Project Gutenberg catalog from {config.CATALOG_URL}...")
        try:
            async with aiohttp.ClientSession(headers={'User-Agent': utils.get_random_user_agent()}) as session:
                async with session.get(config.CATALOG_URL) as response:
                    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
                    async with aiofiles.open(temp_zip_path, 'wb') as f:
                        while True:
                            chunk = await response.content.read(8192) # 8KB chunks
                            if not chunk:
                                break
                            await f.write(chunk)
                    logging.info(f"Catalog downloaded successfully to {temp_zip_path}")
                    return True
        except aiohttp.ClientError as e:
            logging.error(f"Error downloading catalog: {e}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred during catalog download: {e}")
            return False

    def _parse_rdf_and_extract_links(
        self,
        rdf_content: str,
        downloaded_urls: Set[str],
        keyword_filters: Optional[List[str]] = None
    ) -> List[str]:
        """Parses RDF content and extracts relevant text file links, applying filters."""
        try:
            # Ensure content is bytes for lxml
            if isinstance(rdf_content, str):
                rdf_content_bytes = rdf_content.encode('utf-8')
            else:
                rdf_content_bytes = rdf_content

            if not rdf_content_bytes.strip():
                logging.warning("RDF content is empty. Cannot parse.")
                return []

            tree = etree.fromstring(rdf_content_bytes)
            discovered_links: Set[str] = set() # Use a set to ensure uniqueness before list conversion

            ebook_nodes = tree.xpath('//pgterms:ebook', namespaces=NAMESPACES)
            logging.info(f"Found {len(ebook_nodes)} ebook entries in catalog.")

            total_links_before_keyword_filter = 0
            links_after_keyword_filter = 0

            for ebook_node in ebook_nodes:
                ebook_id_attr = ebook_node.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about')
                if ebook_id_attr:
                    ebook_id = ebook_id_attr.replace('ebooks/', '')
                else:
                    continue # Skip if no ID

                # Keyword Filtering Logic
                if keyword_filters:
                    title_nodes = ebook_node.xpath('dcterms:title/text()', namespaces=NAMESPACES)
                    title = " ".join(title_nodes).lower() if title_nodes else ""

                    subject_nodes = ebook_node.xpath('dcterms:subject/rdf:Description/rdf:value/text()', namespaces=NAMESPACES)
                    subjects = " ".join(subject_nodes).lower() if subject_nodes else ""

                    bookshelf_nodes = ebook_node.xpath('pgterms:bookshelf/rdf:Description/rdf:value/text()', namespaces=NAMESPACES)
                    bookshelves = " ".join(bookshelf_nodes).lower() if bookshelf_nodes else ""

                    # Combine relevant metadata for searching
                    searchable_metadata = f"{title} {subjects} {bookshelves}"

                    match_found = False
                    for keyword in keyword_filters:
                        if keyword.lower() in searchable_metadata:
                            match_found = True
                            break
                    if not match_found:
                        continue # Skip this ebook if no keyword matches

                # Extract download links for .txt files
                # Common patterns for text links:
                # 1. https://www.gutenberg.org/files/EBOOK_ID/EBOOK_ID-0.txt (new UTF-8)
                # 2. https://www.gutenberg.org/files/EBOOK_ID/EBOOK_ID-8.txt (older Latin-1, often also UTF-8)
                # 3. http://www.gutenberg.org/ebooks/EBOOK_ID.txt.utf-8 (older direct link)
                # 4. https://www.gutenberg.org/cache/epub/EBOOK_ID/pgEBOOK_ID.txt (cache links)
                # We look for dcterms:hasFormat pointing to rdf:value ending with .txt or specific text formats.

                # General approach: find any file link, then check its format.
                file_nodes = ebook_node.xpath('dcterms:hasFormat/pgterms:file', namespaces=NAMESPACES)

                link_added_for_this_ebook = False
                for file_node in file_nodes:
                    file_url = file_node.get('{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about')
                    if not file_url:
                        continue

                    total_links_before_keyword_filter +=1 # Count before format check for filtered items

                    # Check format from rdf:value inside dcterms:format/rdf:Description
                    format_values = file_node.xpath('dcterms:format/rdf:Description/rdf:value/text()', namespaces=NAMESPACES)

                    is_plain_text = False
                    for fmt_val in format_values:
                        fmt_val_lower = fmt_val.lower()
                        if "text/plain" in fmt_val_lower:
                            if file_url.endswith((".txt", ".txt.utf8", ".txt.utf-8")): # Prioritize explicit .txt utf-8
                                is_plain_text = True
                                break
                            # Could also accept if format is text/plain but URL doesn't end with .txt
                            # e.g. some older files might not have .txt extension but are text/plain
                            # For now, being strict to .txt helps avoid non-text files.

                    if is_plain_text:
                        # Normalize URL: prefer https, ensure www.gutenberg.org
                        if file_url.startswith("http://"):
                            file_url = file_url.replace("http://", "https://", 1)
                        if not file_url.startswith("https://www.gutenberg.org"):
                            # Handle cases like "http://gutenberg.org" or relative paths if any
                            # For now, assuming absolute URLs from catalog are mostly correct domain-wise
                            if "gutenberg.org" not in file_url: # if it's a relative path or wrong domain
                                logging.debug(f"Skipping potentially malformed or non-Gutenberg URL: {file_url}")
                                continue

                        if file_url not in downloaded_urls:
                            discovered_links.add(file_url)
                            link_added_for_this_ebook = True # Mark that a link was added for this ebook

                if keyword_filters and link_added_for_this_ebook:
                    links_after_keyword_filter +=1


            if keyword_filters:
                logging.info(f"Keyword filtering: Matched {links_after_keyword_filter} ebooks out of {len(ebook_nodes)} processed after initial filter.")

            logging.info(f"Discovered {len(discovered_links)} new unique text links from catalog.")
            return list(discovered_links)

        except etree.XMLSyntaxError as e:
            logging.error(f"Error parsing RDF XML: {e}. Content preview (first 500 chars): {rdf_content_bytes[:500]!r}")
            return []
        except Exception as e:
            logging.error(f"An unexpected error occurred during RDF parsing and link extraction: {e}")
            return []


    async def discover_links(self, downloaded_urls: Set[str], keyword_filters: Optional[List[str]] = None) -> List[str]:
        """
        Downloads, extracts, and parses the Project Gutenberg catalog to find .txt file links.
        Applies keyword filtering if specified.
        """
        os.makedirs(config.TEMP_DIR, exist_ok=True)
        temp_zip_path = os.path.join(config.TEMP_DIR, "catalog.rdf.zip")
        rdf_file_name_in_zip = "catalog.rdf" # This might need adjustment based on actual zip structure, e.g. "cache/epub/catalog.rdf"

        # Try to find the exact rdf file name, usually 'catalog.rdf' or 'pgterms_catalog.rdf' or similar in a subdirectory
        # For now, assume it's 'catalog.rdf' at some level. The _extract_zip_member will use endswith.

        # Download the catalog
        download_success = await self._download_catalog(temp_zip_path)
        if not download_success:
            return []

        # Decompress the catalog.rdf file
        loop = asyncio.get_event_loop()
        # The actual member name inside the zip might be like 'cache/epub/catalog.rdf/catalog.rdf' or just 'catalog.rdf'
        # We will tell _extract_zip_member to look for a file ending with 'catalog.rdf'
        extracted_rdf_path = await loop.run_in_executor(
            None, self._extract_zip_member, temp_zip_path, rdf_file_name_in_zip, config.TEMP_DIR
        )

        if not extracted_rdf_path:
            logging.error("Failed to extract catalog.rdf from the zip.")
            try:
                os.remove(temp_zip_path)
            except OSError: pass # Ignore if removal fails
            return []

        # Read the RDF file content
        try:
            async with aiofiles.open(extracted_rdf_path, 'r', encoding='utf-8') as f:
                rdf_content = await f.read()
        except Exception as e:
            logging.error(f"Error reading extracted RDF file {extracted_rdf_path}: {e}")
            try:
                os.remove(temp_zip_path)
                os.remove(extracted_rdf_path)
            except OSError: pass
            return []

        # Parse RDF and extract links
        final_links = self._parse_rdf_and_extract_links(rdf_content, downloaded_urls, keyword_filters)

        # Clean up temporary files
        try:
            os.remove(temp_zip_path)
            logging.info(f"Deleted temporary zip file: {temp_zip_path}")
            os.remove(extracted_rdf_path)
            logging.info(f"Deleted temporary RDF file: {extracted_rdf_path}")
        except OSError as e:
            logging.warning(f"Error deleting temporary files: {e}")

        return final_links


if __name__ == '__main__':
    # Example usage for testing GutenbergTarget directly
    async def main_test():
        # Setup mock config for testing if not using actual config from project
        # This is especially important for CATALOG_URL
        class TestConfig(MockConfig): # Inherit from MockConfig to get TEMP_DIR etc.
             # Provide a URL to a smaller, real RDF.zip for testing if possible,
             # or ensure the mock _download_catalog creates a realistic dummy zip.
             # For now, we'll rely on mocks creating dummy files.
             CATALOG_URL = "http://www.gutenberg.org/cache/epub/catalog.rdf.zip" # Real one for potential live test
             # To test offline, you'd need a local catalog.rdf.zip and adjust _download_catalog or this URL.

        config.CATALOG_URL = TestConfig.CATALOG_URL # Override mock config's potentially bad URL

        # Create dummy catalog.rdf.zip and catalog.rdf for mock testing if download is mocked
        # This part is tricky because the mocks are inside the class.
        # The ideal test would involve providing a small, real (or realistic dummy) catalog.rdf.zip

        # For a simple test, let's assume _download_catalog and _extract_zip_member
        # are either tested independently or mocked effectively to produce a catalog.rdf.
        # Here, we can manually create a dummy catalog.rdf if the download/extract is too complex to mock simply.

        dummy_rdf_content = """
        <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                 xmlns:dcterms="http://purl.org/dc/terms/"
                 xmlns:pgterms="http://www.gutenberg.org/2009/pgterms/">
          <pgterms:ebook rdf:about="ebooks/1">
            <dcterms:title>The Declaration of Independence of the United States of America</dcterms:title>
            <dcterms:subject>
              <rdf:Description>
                <rdf:value>United States -- History -- Revolution, 1775-1783 -- Sources</rdf:value>
              </rdf:Description>
            </dcterms:subject>
            <dcterms:hasFormat>
              <pgterms:file rdf:about="http://www.gutenberg.org/files/1/1-0.txt">
                <dcterms:format>
                  <rdf:Description>
                    <rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">text/plain; charset=utf-8</rdf:value>
                  </rdf:Description>
                </dcterms:format>
              </pgterms:file>
            </dcterms:hasFormat>
             <dcterms:hasFormat>
              <pgterms:file rdf:about="https://www.gutenberg.org/ebooks/1.txt.utf-8">
                <dcterms:format>
                  <rdf:Description>
                    <rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">text/plain; charset=utf-8</rdf:value>
                  </rdf:Description>
                </dcterms:format>
              </pgterms:file>
            </dcterms:hasFormat>
          </pgterms:ebook>
          <pgterms:ebook rdf:about="ebooks/2">
            <dcterms:title>The United States Bill of Rights</dcterms:title>
            <dcterms:subject>
                <rdf:Description><rdf:value>Constitutional law -- United States -- Sources</rdf:value></rdf:Description>
            </dcterms:subject>
            <pgterms:bookshelf>
                <rdf:Description><rdf:value>Politics</rdf:value></rdf:Description>
            </pgterms:bookshelf>
            <dcterms:hasFormat>
              <pgterms:file rdf:about="http://www.gutenberg.org/files/2/2.txt">
                <dcterms:format>
                  <rdf:Description>
                    <rdf:value rdf:datatype="http://purl.org/dc/terms/IMT">text/plain; charset=us-ascii</rdf:value>
                  </rdf:Description>
                </dcterms:format>
              </pgterms:file>
            </dcterms:hasFormat>
          </pgterms:ebook>
           <pgterms:ebook rdf:about="ebooks/3">
            <dcterms:title>A Random Book About AI</dcterms:title>
            <dcterms:hasFormat>
              <pgterms:file rdf:about="http://www.gutenberg.org/files/3/3-0.txt">
                <dcterms:format><rdf:Description><rdf:value>text/plain; charset=utf-8</rdf:value></rdf:Description></dcterms:format>
              </pgterms:file>
            </dcterms:hasFormat>
          </pgterms:ebook>
        </rdf:RDF>
        """
        # Manually place a dummy catalog.rdf for the parser to use, bypassing download/extract for this test unit
        os.makedirs(config.TEMP_DIR, exist_ok=True)
        dummy_rdf_path = os.path.join(config.TEMP_DIR, "catalog.rdf") # This should match what _extract_zip_member would produce

        # Monkey patch parts of the discover_links for this test
        original_download = GutenbergTarget._download_catalog
        original_extract = GutenbergTarget._extract_zip_member

        async def mock_download(self, temp_zip_path: str):
            # Simulate successful download of a zip, but we don't need the zip itself if we create catalog.rdf
            logging.info("Mock download: SKIPPED, assuming zip is there or not needed for this test flow.")
            # To make it more robust, this mock could create a dummy zip containing the dummy_rdf_content
            return True

        def mock_extract(self, zip_file_path: str, member_name: str, dest_path: str):
            # Simulate extraction by writing the dummy RDF content to the expected path
            logging.info(f"Mock extract: Writing dummy RDF to {dummy_rdf_path}")
            with open(dummy_rdf_path, "w", encoding="utf-8") as f:
                f.write(dummy_rdf_content)
            return dummy_rdf_path

        GutenbergTarget._download_catalog = mock_download # type: ignore
        GutenbergTarget._extract_zip_member = mock_extract # type: ignore

        target = GutenbergTarget()
        print(f"Target Name: {await target.get_target_name()}")

        print("\n--- Test Case 1: No filters, no downloaded URLs ---")
        links1 = await target.discover_links(downloaded_urls=set())
        print(f"Discovered links: {len(links1)}")
        for link in links1: print(link)
        # Expected: 3 links (1-0.txt, 1.txt.utf-8, 2.txt, 3-0.txt)

        print("\n--- Test Case 2: With keyword filter 'United States' ---")
        links2 = await target.discover_links(downloaded_urls=set(), keyword_filters=["United States"])
        print(f"Discovered links with filter 'United States': {len(links2)}")
        for link in links2: print(link)
        # Expected: 3 links (1-0.txt, 1.txt.utf-8 from ebook 1; 2.txt from ebook 2)

        print("\n--- Test Case 3: With keyword filter 'AI' ---")
        links3 = await target.discover_links(downloaded_urls=set(), keyword_filters=["AI"])
        print(f"Discovered links with filter 'AI': {len(links3)}")
        for link in links3: print(link)
        # Expected: 1 link (3-0.txt from ebook 3)

        print("\n--- Test Case 4: Filter with 'politics' and one URL already downloaded ---")
        downloaded = {"https://www.gutenberg.org/files/2/2.txt"} # ebook 2's link
        links4 = await target.discover_links(downloaded_urls=downloaded, keyword_filters=["politics"])
        print(f"Discovered links (filter 'politics', 1 downloaded): {len(links4)}")
        for link in links4: print(link)
        # Expected: 0 links (ebook 2 matches 'politics' but its link is already downloaded)

        # Restore original methods if other tests in same suite depend on them
        GutenbergTarget._download_catalog = original_download # type: ignore
        GutenbergTarget._extract_zip_member = original_extract # type: ignore

        # Cleanup
        if os.path.exists(dummy_rdf_path): os.remove(dummy_rdf_path)

    if __name__ == '__main__':
        asyncio.run(main_test())
