import aiohttp
import asyncio
import argparse
from tqdm import tqdm
import sqlite3

# change this to how fast you want it, 2 is a good start increase if needed. 
MAX_CONCURRENT_SCANS = 2
CHECK_STATUS_INTERVAL = 5

# SQLMap API URL
SQLMAP_API_URL = 'http://127.0.0.1:8775'

sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

async def check_sqlmap_api_status():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'{SQLMAP_API_URL}/version') as response:
                return response.status == 200
    except aiohttp.ClientError:
        return False

async def create_task_and_start_scan(ip, sqlmap_args, live_ips, progress_bar):
    # Check if SQLMap API is running before starting the scan
    api_running = await check_sqlmap_api_status()
    if not api_running:
        tqdm.write(f"SQLMap API is not running. Please start the SQLMap API and try again.")
        return

    # Step 1: Create a new task and get the task ID
    async with aiohttp.ClientSession() as session:
        async with session.get(f'{SQLMAP_API_URL}/task/new') as response:
            response_data = await response.json()
            task_id = response_data.get('taskid', '')
            if not task_id:
                tqdm.write(f"Error creating a new task for {ip}.")
                return

            #tqdm.write(f"Started scan for {ip}. Task ID: {task_id}")
            # if the ip is not in the database, add it
            conn = sqlite3.connect('scans.db')
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS scans (ip TEXT, task_id TEXT)")
            cursor.execute("SELECT * FROM scans WHERE ip=?", (ip,))
            result = cursor.fetchone()
            if result is None:
                cursor.execute("INSERT INTO scans (ip, task_id) VALUES (?, ?)", (ip, task_id))
                conn.commit()
            conn.close()

    # Step 2: Start the scan for the specified URL with SQLMap arguments
    async with aiohttp.ClientSession() as session:
        with open(sqlmap_args, 'r') as args_file:
            sqlmap_arguments = args_file.read().strip()
        scan_data = {"url": f"{ip}/ {sqlmap_arguments}"}
        async with session.post(f'{SQLMAP_API_URL}/scan/{task_id}/start', json=scan_data) as response:
            response_data = await response.json()
            if not response_data.get('success', False):
                tqdm.write(f"Error starting scan for {ip}.")
                return

            engine_id = response_data.get('engineid', '')
            #tqdm.write(f"Scan started for {ip}. Engine ID: {engine_id}")

    # Step 3: Check the status periodically until the scan is finished (terminated)
    while True:
        tasks_status = await get_tasks_status()
        task_status = tasks_status.get(task_id, '')

        if task_status.lower() == 'terminated':
            # Write the ip and task_id to a MySQL SQLite database file

            #tqdm.write(f"Scan for {ip} finished. - {task_id}")
            break
        else:
            await asyncio.sleep(CHECK_STATUS_INTERVAL)

    live_ips.append(ip)
    progress_bar.update(1)

async def get_tasks_status():
    async with aiohttp.ClientSession() as session:
        async with session.get(f'{SQLMAP_API_URL}/admin/list') as response:
            response_data = await response.json()
            tasks = response_data.get('tasks', {})
            return tasks

async def main():
    # ASW BANNER
    cool_banner = """

                     ░▒▓██████▓▒░       ░▒▓███████▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                    ░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░            ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                    ░▒▓█▓▒░░▒▓█▓▒░     ░▒▓█▓▒░            ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                    ░▒▓████████▓▒░      ░▒▓██████▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                    ░▒▓█▓▒░░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                    ░▒▓█▓▒░░▒▓█▓▒░            ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                    ░▒▓█▓▒░░▒▓█▓▒░     ░▒▓███████▓▒░       ░▒▓█████████████▓▒░                                           

                            [+]  Agressive SQLMAP Wrapper [+]
    """
    print(cool_banner)
    parser = argparse.ArgumentParser(description='Agressive SQLMap Wrapper.')
    parser.add_argument('--args_file', type=str, help='Path to the file containing SQLMap arguments.')
    parser.add_argument('--input_file', type=str, default='sqlmap_targets/sorted.txt', help='Path to the file containing live target IPs.')
    args = parser.parse_args()
    # Check if SQLMap API is running
    api_running = await check_sqlmap_api_status()
    if not api_running:
        tqdm.write("SQLMap API is not running. Please start the SQLMap API using the following command:")
        tqdm.write("sqlmapapi -s -H '0.0.0.0'")
        return

    live_ips = []
    with open(args.input_file, 'r') as file:
        live_ips = [line.strip() for line in file.readlines()]
    progress_bar = tqdm(total=len(live_ips), desc="Scanning IPs", dynamic_ncols=True)
    scan_tasks = [create_task_and_start_scan(ip, args.args_file, live_ips, progress_bar) for ip in live_ips]
    await asyncio.gather(*scan_tasks)
    progress_bar.close()

if __name__ == "__main__":
    asyncio.run(main())