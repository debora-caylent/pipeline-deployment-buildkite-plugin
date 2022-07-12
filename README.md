# pipeline-deployment-buildkite-plugin
Build + deploy ecs services

# Step 1: Create a new git repository
# Step 2: Add a plugin.yml
```
name: File Counter
description: Annotates the build with a file count
author: https://github.com/a-github-user
requirements: []
configuration:
  properties:
    pattern:
      type: string
  additionalProperties: false
```
## Valid plugin.yml properties
Property	Description
name	The name of the plugin, in Title Case.
description	A short sentence describing what the plugin does.
author	A URL to the plugin author (for example, website or GitHub profile).
requirements	An array of commands that are expected to exist in the agent's $PATH.
configuration	A JSON Schema describing the valid configuration options available.
# Step 3: Validate the plugin.yml
`docker-compose run --rm lint`