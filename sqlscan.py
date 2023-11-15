import aiohttp
import asyncio
import argparse
from tqdm import tqdm

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

async def check_ip(ip, progress_bar):
    protocols = ['http', 'https']
    live = False
    
    for protocol in protocols:
        url = f'{protocol}://{ip}'
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    if response.status < 400:
                        live = True
                        break  # If any protocol is live, break out of the loop
        except (asyncio.TimeoutError, aiohttp.ClientError):
            continue  # Continue to the next protocol in case of timeout or client error
    
    progress_bar.update(ip, live)
    return (ip, None) if not live else (ip, 200)  # Return (ip, None) if not live, otherwise (ip, 200)


async def create_task_and_start_scan(ip, sqlmap_args, live_ips, progress_bar):
    # Check if SQLMap API is running before starting the scan
    api_running = await check_sqlmap_api_status()
    if not api_running:
        print(f"SQLMap API is not running. Please start the SQLMap API and try again.")
        return

    # Step 1: Create a new task and get the task ID
    async with aiohttp.ClientSession() as session:
        async with session.get(f'{SQLMAP_API_URL}/task/new') as response:
            response_data = await response.json()
            task_id = response_data.get('taskid', '')
            if not task_id:
                print(f"Error creating a new task for {ip}.")
                return

            print(f"Started scan for {ip}. Task ID: {task_id}")

    # Step 2: Start the scan for the specified URL with SQLMap arguments
    async with aiohttp.ClientSession() as session:
        with open(sqlmap_args, 'r') as args_file:
            sqlmap_arguments = args_file.read().strip()
        scan_data = {'url': f'http://{ip} {sqlmap_arguments}'}
        async with session.post(f'{SQLMAP_API_URL}/scan/{task_id}/start', json=scan_data) as response:
            response_data = await response.json()
            if not response_data.get('success', False):
                print(f"Error starting scan for {ip}.")
                return

            engine_id = response_data.get('engineid', '')
            print(f"Scan started for {ip}. Engine ID: {engine_id}")

    # Step 3: Check the status periodically until the scan is finished (terminated)
    while True:
        tasks_status = await get_tasks_status()
        task_status = tasks_status.get(task_id, '')

        if task_status.lower() == 'terminated':
            print(f"Scan for {ip} finished.")
            break
        else:
            await asyncio.sleep(CHECK_STATUS_INTERVAL)

    live_ips.append(ip)
    progress_bar.update(ip)

async def get_tasks_status():
    async with aiohttp.ClientSession() as session:
        async with session.get(f'{SQLMAP_API_URL}/admin/list') as response:
            response_data = await response.json()
            tasks = response_data.get('tasks', {})
            return tasks

class ProgressBar:
    def __init__(self, total):
        self.total = total
        self.progress = 0
        self.live_count = 0
        self.scanned_count = 0

    def update(self, ip, is_live):
        self.progress += 1
        self.scanned_count += 1
        self.live_count += 1 if is_live else 0
        percent_complete = (self.progress / self.total) * 100
        print(f"\rScanning IPs: {ip} | Progress: {percent_complete:.2f}% | Targets Scanned: {self.scanned_count} | Live IPs: {self.live_count}", end='', flush=True)
        if self.progress == self.total:
            print()  # Move to the next line after the progress is complete

async def main():
    parser = argparse.ArgumentParser(description='Asynchronous SQLMap scanner.')
    parser.add_argument('--args_file', type=str, help='Path to the file containing SQLMap arguments.')
    parser.add_argument('--input_file', type=str, default='input_file.txt', help='Path to the input file containing target IPs.')
    args = parser.parse_args()

    # Check if SQLMap API is running
    api_running = await check_sqlmap_api_status()
    if not api_running:
        print("SQLMap API is not running. Please start the SQLMap API using the following command:")
        print("sqlmapapi -s -H '0.0.0.0'")
        return

    target_ips = []
    with open(args.input_file, 'r') as file:
        target_ips = [line.strip() for line in file.readlines()]

    live_ips = []
    progress_bar = ProgressBar(len(target_ips))

    # Use asyncio.gather to await the completion of the tasks
    results = await asyncio.gather(*[check_ip(ip, progress_bar) for ip in target_ips])

    with open('live.txt', 'w') as file:
        for ip, _ in results:
            if ip:
                live_ips.append(ip)
                file.write(f"{ip}\n")

    scan_progress_bar = ProgressBar(len(live_ips))
    scan_tasks = [create_task_and_start_scan(ip, args.args_file, live_ips, scan_progress_bar) for ip in live_ips]
    await asyncio.gather(*scan_tasks)

if __name__ == "__main__":
    asyncio.run(main())
