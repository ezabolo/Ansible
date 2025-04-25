#!/usr/bin/env python3
import csv
import re
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.plugins.callback import CallbackBase
from ansible.module_utils.common.collections import ImmutableDict
from ansible import context
import ansible.constants as C
import os
import datetime

# Define package lists
web_packages = [
    'gnome*',
    'firefox',
    'google-chrome',
    'ftp',
    'telnet',
    'nmap',
    'ImageMagick',
    'cups'
]

db_packages = [
    'gnome*',
    'firefox',
    'google-chrome',
    'ftp',
    'telnet',
    'nmap',
    'cups'
]

# Custom callback to capture results
class ResultCallback(CallbackBase):
    def __init__(self):
        super(ResultCallback, self).__init__()
        self.host_results = {}

    def v2_runner_on_ok(self, result):
        host = result._host.get_name()
        if host not in self.host_results:
            self.host_results[host] = {}
        
        if 'ansible_facts' in result._result:
            if 'packages' in result._result['ansible_facts']:
                self.host_results[host].update(result._result['ansible_facts']['packages'])
        
        if 'stdout_lines' in result._result:
            package_name = result._task.get_name()
            self.host_results[host][package_name] = result._result['stdout_lines']


def main():
    # Initialize Ansible objects
    context.CLIARGS = ImmutableDict(connection='local', module_path=['/usr/share/ansible'], 
                                   forks=10, become=None, become_method=None, become_user=None, 
                                   check=False, diff=False, verbosity=0)
    
    loader = DataLoader()
    inventory = InventoryManager(loader=loader, sources=['inventory.ini'])
    variable_manager = VariableManager(loader=loader, inventory=inventory)
    
    results_callback = ResultCallback()
    
    # Dictionary to store the final results
    server_package_results = {}
    
    # Process each host in inventory
    for host in inventory.get_hosts():
        hostname = host.get_name()
        print(f"Checking packages on {hostname}...")
        
        # Determine which package list to check based on hostname
        if re.search(r'web', hostname, re.IGNORECASE):
            packages_to_check = web_packages
            server_type = "web"
        elif re.search(r'db', hostname, re.IGNORECASE):
            packages_to_check = db_packages
            server_type = "db"
        else:
            continue  # Skip hosts that don't match web or db pattern
        
        server_package_results[hostname] = {"type": server_type, "packages": {}}
        
        # Create task for each package
        for package in packages_to_check:
            if "*" in package:
                # For wildcard packages, use shell module to check
                task = dict(
                    action=dict(
                        module='shell',
                        args=f"rpm -qa | grep -i '{package}' || true"
                    ),
                    name=package
                )
            else:
                # For specific packages, use package_facts module
                task = dict(
                    action=dict(
                        module='package_facts',
                        manager='auto'
                    ),
                    name="Get package facts"
                )
            
            # Create play and run it
            play = Play().load(dict(
                name=f"Check {package} on {hostname}",
                hosts=hostname,
                gather_facts='no',
                tasks=[task]
            ), variable_manager=variable_manager, loader=loader)
            
            tqm = None
            try:
                tqm = TaskQueueManager(
                    inventory=inventory,
                    variable_manager=variable_manager,
                    loader=loader,
                    passwords=dict(),
                    stdout_callback=results_callback
                )
                tqm.run(play)
            finally:
                if tqm is not None:
                    tqm.cleanup()
            
            # Process results for this package
            if hostname in results_callback.host_results:
                # Check if we got package facts or shell output
                if package in results_callback.host_results[hostname]:
                    # This is shell output for wildcard packages
                    output = results_callback.host_results[hostname][package]
                    if output and any(output):
                        server_package_results[hostname]["packages"][package] = True
                    else:
                        server_package_results[hostname]["packages"][package] = False
                elif "Get package facts" in results_callback.host_results[hostname]:
                    # This is for specific packages using package_facts
                    package_data = results_callback.host_results[hostname]
                    # Check if the package exists in any format (different package managers name differently)
                    package_found = False
                    for pkg_name in package_data.keys():
                        if package.lower() in pkg_name.lower():
                            package_found = True
                            break
                    server_package_results[hostname]["packages"][package] = package_found
    
    # Generate CSV output
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"package_report_{timestamp}.csv"
    
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['Server', 'Type'] + (web_packages if len(web_packages) > len(db_packages) else db_packages)
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for server, data in server_package_results.items():
            row = {'Server': server, 'Type': data['type']}
            for pkg, installed in data['packages'].items():
                row[pkg] = "Installed" if installed else "Not Installed"
            writer.writerow(row)
    
    print(f"Report generated: {csv_filename}")

if __name__ == "__main__":
    main()
