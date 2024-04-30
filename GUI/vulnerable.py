import aiohttp
import asyncio
import argparse
from tqdm import tqdm
import sqlite3

# this script reads the database file from sqlscan.py and reads the log for each task_id to determine if the target is vulnerable or if an injection point was found.


async def get_log(task_id):
    async with aiohttp.ClientSession() as session:
        async with session.get(f'http://localhost:8775/scan/{task_id}/log') as response:
            if response.status == 200:
                response_data = await response.json()
                # for every entry in the json log response, return the message
                for entry in response_data.get('log', []):
                    if "appears to be" in entry['message']:
                        return "vulnerable"
                    else:
                        return "Not vulnerable"


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
        print(f"{ip} - {task_id} - {log}")

    conn.close()

if __name__ == "__main__":
    asyncio.run(main())
