import aiohttp
import asyncio
import argparse
from tqdm import tqdm
import sqlite3

async def get_log(task_id):
    async with aiohttp.ClientSession() as session:
        async with session.get(f'http://localhost:8775/scan/{task_id}/log') as response:
            if response.status == 200:
                response_data = await response.json()
                return response_data.get('log', '')

async def main():
    # show a list of ips and their status ( vulnerable )
    parser = argparse.ArgumentParser(description='Check the status of SQLMap scans.')
    parser.add_argument('--db_file', required=True, help='Path to the SQLite database file.')
    args = parser.parse_args()

    conn = sqlite3.connect(args.db_file)
    cursor = conn.cursor()

    cursor.execute("SELECT ip, task_id FROM scans")
    results = cursor.fetchall()

    for ip, task_id in results:
        log = await get_log(task_id)
        for entry in log:
            if "appears to be" in entry.get("message", ""):
                print(f"Task ID: {task_id}, Target IP: {ip}")

    conn.close()

if __name__ == "__main__":
    asyncio.run(main())
