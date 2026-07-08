#!/usr/bin/python3
import asyncio
import aiohttp
from typing import Self, Final
from time import perf_counter
from collections import defaultdict
from bs4 import BeautifulSoup
from pprint import pprint

# class for exceptions working with api metroethernet.ru
class MacVendorAPIError(Exception):
    pass

# context manager api to identify mac's vendor
class MacVendorIdentifier:
    # one api for any object
    URL: Final[str] = "https://metroethernet.ru/tools/oui/find"

    _semaphore: asyncio.Semaphore
    _session: aiohttp.ClientSession | None

    # initialize by semaphore with 200 limit by default
    def __init__(self, max_concurrent: int = 200) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._session = None

    # create asynchronous http session
    async def __aenter__(self) -> Self:
        self._session = aiohttp.ClientSession()
        return self
    
    # close http session while exiting
    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session:
            await self._session.close()

    # get vendor name from api for mac address
    async def get_mac_vendor(self, mac: str) -> str:
        # payload including mac
        payload = {"address": mac}

        # wait for semaphore to avoid spamming
        async with self._semaphore:
            try:
                # use async post method
                async with self._session.post(MacVendorIdentifier.URL, data=payload) as response:
                    # raise error status if occured
                    if response.status != 200:
                        raise MacVendorAPIError(f"Error: response status is {response.status}")
                    
                    # parse response text with BeautifulSoup
                    soup = BeautifulSoup(await response.text(), "html.parser")

                    # return vendor if found
                    vendor_class = soup.find("td", class_="tools-oui-vendor")
                    if vendor_class:
                        return vendor_class.text.strip()
                    
                    # return not found error if there's no information about this mac
                    error_div = soup.select_one("div[style*='text-align: center']")
                    if error_div:
                        return "Vendor not found"

                    # raise unhandled error if api response wasn't parsed correctly
                    raise MacVendorAPIError("unhandled response")
            
            # return exception wrapping in custom exception
            except Exception as exc:
                if isinstance(exc, MacVendorAPIError):
                    raise
                raise MacVendorAPIError(f"Network error: {exc}") from exc

# test function to 
async def test_api_with_many_macs() -> None:
    # parse fdb table from file to get macs
    def get_macs_from_file() -> list[str]:
        with open("v2/macs.txt", "r") as file:
            return [line.split()[2] for line in file]
    
    # count vendors occurencies
    vendors = defaultdict(int)
    macs_count, unknown_macs_count = 0, 0
    start_time = perf_counter()

    # use api as a context manager
    async with MacVendorIdentifier() as api:
        # get macs
        macs = get_macs_from_file()
        macs_count = len(macs)

        # create and gather tasks identifying each mac
        tasks = [api.get_mac_vendor(mac) for mac in macs]
        results = await asyncio.gather(*tasks, return_exceptions=True)   # return exceptions as results

        for result in results:
            # print exception is occured
            if isinstance(result, Exception):
                print(f"{result}")
            # count unknown vendors
            elif result == "Vendor not found":
                unknown_macs_count += 1
            # count each successfully identified vendor
            else:
                vendors[result] += 1

    # sort dict by vendors count
    vendors = dict(sorted(vendors.items(), key=lambda x: x[1], reverse=True))

    duration = perf_counter() - start_time
    average = duration / macs_count

    pprint(vendors, sort_dicts=False)
    print(f"""Vendors count: {len(vendors)}
MACs count: {macs_count}
Unknown MACs count: {unknown_macs_count}
Time: {duration * 1000:.1f} ms
Average time for MAC: {average * 1000:.1f} ms""")


asyncio.run(test_api_with_many_macs())