import gitlab
import os
import signal
import sys
import time
import threading
from gitlab.exceptions import GitlabGetError
from functools import wraps

class TimeoutError(Exception):
    pass

# Decorator for timeout using threading (more portable than SIGALRM)
def timeout(seconds):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            error = [None]
            
            def worker():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    error[0] = e
            
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            thread.join(seconds)
            
            if thread.is_alive():
                raise TimeoutError("Operation timed out")
            
            if error[0] is not None:
                raise error[0]
                
            return result[0]
        return wrapper
    return decorator

@timeout(10)
def scan_repository(full_project, default_branch):
    tree = full_project.repository_tree(recursive=True, ref=default_branch, all=True)
    
    for item in tree:
        path = item['path']
        if path.endswith(('.yml', '.yaml', '.py', '.js')):
            try:
                file_content = full_project.files.get(file_path=path, ref=default_branch)
                try:
                    content = file_content.decode()
                except (TypeError, UnicodeDecodeError):
                    content = file_content.content
                    if isinstance(content, bytes):
                        content = content.decode('utf-8', errors='ignore')
                
                if any(tok in content.lower() for tok in ['lambda_handler', 'exports.handler', 'serverless']):
                    return True, path
            except (GitlabGetError, Exception):
                continue
    return False, None

# Handle Ctrl+C gracefully
def interrupt_handler(sig, frame):
    print("\nGracefully stopping... (this may take a moment)")
    print("\nPartial results:")
    if lambda_repos:
        for name, path in lambda_repos:
            print(f" • {name} (found in: {path})")
    else:
        print("No Lambda code found yet in scanned projects.")
    sys.exit(0)

signal.signal(signal.SIGINT, interrupt_handler)

# 1. Connect
token = os.getenv('GITLAB_TOKEN')
if not token:
    raise ValueError("Please set the GITLAB_TOKEN environment variable")

gl = gitlab.Gitlab('https://gitlab.com', private_token=token)

# Get group ID from environment variable
group_id = os.getenv('GITLAB_GROUP_ID')
if not group_id:
    raise ValueError("Please set the GITLAB_GROUP_ID environment variable")

# 2. Get all projects in a group
group = gl.groups.get(int(group_id))
print(f"\nSearching in group: {group.name}")

lambda_repos = []
projects = group.projects.list(all=True, include_subgroups=True)
total_projects = len(projects)

print(f"Found {total_projects} projects to scan\n")

for idx, project in enumerate(projects, 1):
    print(f"[{idx}/{total_projects}] Checking project: {project.name}", end='', flush=True)
    try:
        # Get the full project object
        full_project = gl.projects.get(project.id)
        default_branch = full_project.default_branch or 'main'
        
        try:
            has_lambda, path = scan_repository(full_project, default_branch)
            if has_lambda:
                lambda_repos.append((full_project.name, path))
                print(f"\r[{idx}/{total_projects}] ✓ Found Lambda code in: {full_project.name} (file: {path})")
            else:
                print("\r" + " " * 100 + f"\r[{idx}/{total_projects}] Checked {project.name}")
                
        except TimeoutError:
            print(f"\r[{idx}/{total_projects}] ⚠ Skipping {project.name}: scan took too long (>10 seconds)")
            continue
        except GitlabGetError as e:
            if '404' not in str(e):  # Only print warning if it's not a 404
                print(f"\r[{idx}/{total_projects}] Warning: Could not access repository tree for {full_project.name}: {str(e)}")
            else:
                print("\r" + " " * 100 + f"\r[{idx}/{total_projects}] Checked {project.name}")
            continue
        except Exception as e:
            print(f"\r[{idx}/{total_projects}] Error processing project {full_project.name}: {str(e)}")
            continue
            
    except GitlabGetError as e:
        if '404' not in str(e):  # Only print warning if it's not a 404
            print(f"\r[{idx}/{total_projects}] Warning: Could not access project {project.name}: {str(e)}")
        else:
            print("\r" + " " * 100 + f"\r[{idx}/{total_projects}] Checked {project.name}")
        continue
    except Exception as e:
        print(f"\r[{idx}/{total_projects}] Error processing project {project.name}: {str(e)}")
        continue

# 5. Output
print("\nScan completed!")
print("\nProjects containing Lambda code:")
if lambda_repos:
    for name, path in lambda_repos:
        print(f" • {name} (found in: {path})")
else:
    print("No Lambda code found in any projects.")
