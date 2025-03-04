import subprocess
import json
import os
import argparse

def run_pydeps(script_path, include_pylib=False):
    """Run pydeps on the given script and return parsed JSON output."""
    command = [
        "pydeps",
        "--show-deps",
        "--no-output",
        script_path
    ]
    if include_pylib:
        command.append("--pylib")

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running pydeps: {e.stderr}")
        return None
    except json.JSONDecodeError:
        print("Error parsing JSON output from pydeps.")
        return None

def make_paths_relative(dependencies, base_dir):
    """Convert absolute paths in dependencies to relative paths based on the script's directory."""
    for dep in dependencies.values():
        if "path" in dep and dep["path"]:
            if dep["path"].startswith(base_dir):
                dep["path"] = os.path.relpath(dep["path"], base_dir)
    return dependencies

def save_dependencies(script_path, output_file, include_pylib=False):
    """Run pydeps, process paths, and save the output as JSON."""
    dependencies = run_pydeps(script_path, include_pylib)
    if dependencies:
        script_dir = os.path.dirname(os.path.abspath(script_path))
        dependencies = make_paths_relative(dependencies, script_dir)
        with open(output_file, "w") as f:
            json.dump(dependencies, f, indent=2)
        print(f"Dependencies written to {output_file}")

def ensure_telegram_bot():
    if not os.path.exists("telegram_bot"):
        subprocess.run(["git", "clone", "https://github.com/calhounpaul/telegram_bot"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Python dependencies.")
    parser.add_argument("script_path", nargs="?", default="./telegram_bot/bot.py", help="Path to the script to analyze.")
    args = parser.parse_args()

    ensure_telegram_bot()
    save_dependencies(args.script_path, "deps_min.json")
    save_dependencies(args.script_path, "deps_all.json", include_pylib=True)
