## Pseudocode: crates/history/src/remote_archive.rs

"Remote archive operations using configurable shell commands.
 Commands use placeholder syntax: {0} = first arg, {1} = second arg."

---

### RemoteArchiveConfig (struct)

```
STRUCT RemoteArchiveConfig:
  name       : string
  get_cmd    : string or nil   // template: {0}=remote URL, {1}=local path
  put_cmd    : string or nil   // template: {0}=local path, {1}=remote path
  mkdir_cmd  : string or nil   // template: {0}=remote dir path
```

### RemoteArchiveConfig.is_writable

```
function is_writable(self):
  → self.put_cmd is not nil
```

### RemoteArchiveConfig.is_readable

```
function is_readable(self):
  → self.get_cmd is not nil
```

---

### RemoteArchive (struct)

```
STRUCT RemoteArchive:
  config : RemoteArchiveConfig
```

### new

```
function new(config):
  → RemoteArchive { config }
```

### name

```
function name(self):
  → self.config.name
```

### can_write

```
function can_write(self):
  → self.config.is_writable()
```

### can_read

```
function can_read(self):
  → self.config.is_readable()
```

### Helper: format_command

"Replace {0}, {1}, … placeholders in a command template."

```
function format_command(template, args):
  result = template
  for each (i, arg) in enumerate(args):
    placeholder = "{" + str(i) + "}"
    result = result.replace(placeholder, arg)
  → result
```

### Helper: execute_command

```
async function execute_command(self, command):
  output = shell_exec("sh", "-c", command)

  if output.status is success:
    → ok
  else:
    stderr = output.stderr as string
    → error RemoteCommandFailed {
        command, exit_code: output.status.code, stderr }
```

### put_file

```
async function put_file(self, local_path, remote_path):
  GUARD self.config.put_cmd is nil
    → error RemoteNotConfigured("put command not configured")
  GUARD not file_exists(local_path)
    → error NotFound(local_path)

  command = format_command(put_cmd, [local_path, remote_path])
  → execute_command(command)
```

### mkdir

```
async function mkdir(self, remote_dir):
  GUARD self.config.mkdir_cmd is nil
    → error RemoteNotConfigured("mkdir command not configured")

  command = format_command(mkdir_cmd, [remote_dir])
  → execute_command(command)
```

### get_file

```
async function get_file(self, remote_url, local_path):
  GUARD self.config.get_cmd is nil
    → error RemoteNotConfigured("get command not configured")

  command = format_command(get_cmd, [remote_url, local_path])
  → execute_command(command)
```

### ensure_dir

"Create remote directory if mkdir_cmd is configured.
 Ignores errors (directory may already exist)."

```
async function ensure_dir(self, remote_dir):
  if self.config.mkdir_cmd is not nil:
    ignore_errors { self.mkdir(remote_dir) }
  → ok
```

### put_file_with_mkdir

"Upload a file, creating parent directories as needed."

```
async function put_file_with_mkdir(self, local_path, remote_path):
  parent = parent_dir(remote_path)
  if parent is not nil AND parent != "" AND parent != "/":
    ensure_dir(parent)

  → put_file(local_path, remote_path)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 263    | 82         |
| Functions     | 12     | 12         |
