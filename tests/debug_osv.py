"""Test OSV.dev API directly."""

import asyncio

from myosc.core.models import Package
from myosc.db.osv import OSVClient


async def test_osv():
    client = OSVClient()
    
    # Test with known vulnerable package
    pkg = Package(name="django", version="2.2.0", ecosystem="pypi")
    print(f"Querying OSV for: {pkg.name}=={pkg.version}")
    
    vulns = await client.query_package(pkg)
    print(f"Found {len(vulns)} vulnerabilities:")
    
    for v in vulns[:5]:  # Show first 5
        print(f"  - {v.id}: {v.summary[:60]}...")
    
    await client.close()


if __name__ == "__main__":
    asyncio.run(test_osv())
