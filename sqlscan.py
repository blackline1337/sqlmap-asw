import aiohttp
import asyncio
import argparse
from tqdm import tqdm

MAX_CONCURRENT_SCANS = 2  # Adjust this value based on your desired limit
CHECK_STATUS_INTERVAL = 5  # Adjust this value based on how frequently you want to check the status

# Semaphore to limit concurrent scans
sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

async def check_ip(ip):
    url = f'http://{ip}'  # You can modify the URL format based on your needs
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as response:
                return ip, response.status
    except aiohttp.ClientError:
        return ip, None

async def create_task_and_start_scan(ip, sqlmap_args, progress_bar):
    sqlmap_api_url = 'http://127.0.0.1:8775'

    # Step 1: Create a new task and get the task ID
    async with aiohttp.ClientSession() as session:
        async with session.get(f'{sqlmap_api_url}/task/new') as response:
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
        async with session.post(f'{sqlmap_api_url}/scan/{task_id}/start', json=scan_data) as response:
            response_data = await response.json()
            if not response_data.get('success', False):
                print(f"Error starting scan for {ip}.")
                return

            engine_id = response_data.get('engineid', '')
            print(f"Scan started for {ip}. Engine ID: {engine_id}")

    # Step 3: Check the status periodically until the scan is finished (terminated)
    while True:
        tasks_status = await get_tasks_status(sqlmap_api_url)
        task_status = tasks_status.get(task_id, '')

        if task_status.lower() == 'terminated':
            print(f"Scan for {ip} finished.")
            break
        else:
            progress_bar.update()
            await asyncio.sleep(CHECK_STATUS_INTERVAL)

async def get_tasks_status(sqlmap_api_url):
    async with aiohttp.ClientSession() as session:
        async with session.get(f'{sqlmap_api_url}/admin/list') as response:
            response_data = await response.json()
            tasks = response_data.get('tasks', {})
            return tasks

class ProgressBar:
    def __init__(self, total):
        self.total = total
        self.progress = 0
        self.pbar = tqdm(total=total, desc="Scanning IPs", unit=" IP")

    def update(self):
        self.progress += 1
        self.pbar.update(1)
        self.pbar.set_postfix(remaining=self.total - self.progress, percent=(self.progress / self.total) * 100)

    def close(self):
        self.pbar.close()

async def main():
    parser = argparse.ArgumentParser(description='Asynchronous SQLMap scanner.')
    parser.add_argument('--args_file', type=str, help='Path to the file containing SQLMap arguments.')
    parser.add_argument('--input_file', type=str, default='input_file.txt', help='Path to the input file containing target IPs.')
    args = parser.parse_args()

    target_ips = []  # Initialize an empty list to store target IPs

    # Read target IPs from the input file
    with open(args.input_file, 'r') as file:
        target_ips = [line.strip() for line in file.readlines()]

    live_ips = []  # Initialize an empty list to store live IPs
    tasks = [check_ip(ip) for ip in target_ips]

    # Gather all tasks concurrently
    await asyncio.gather(*tasks)

    # Save live IPs to a file
    with open('live.txt', 'w') as file:
        for ip in live_ips:
            file.write(f"{ip}\n")

    # Start scans for live IPs with SQLMap arguments
    progress_bar = ProgressBar(len(live_ips))
    scan_tasks = [create_task_and_start_scan(ip, args.args_file, progress_bar) for ip in live_ips]
    await asyncio.gather(*scan_tasks)

    progress_bar.close()

if __name__ == "__main__":
    asyncio.run(main())
