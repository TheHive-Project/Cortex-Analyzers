# Slack Responders

![Slack Logo](./assets/slack-logo.png)

This directory contains two Slack responders for TheHive integration:

1. **Slack_CreateChannel**: Creates a Slack channel for a TheHive case, invites participants, and optionally posts a case summary and description.
2. **Slack_SyncChannel**: Syncs Slack channel conversations to TheHive task logs. Imports messages chronologically with file attachments for traceability.

---

## Features

### Slack_CreateChannel
- Creates a Slack channel named `case-<caseId>` (customizable prefix)
- Invites default participants by email
- Sets channel visibility (private or public)
- Posts case summary and/or case description (optional)
- **Automatically tags the case** with `slack:<channel_name>` and `slack-id:<channel_id>` for fast lookups

### Slack_SyncChannel
- **Syncs all Slack channels tagged with `slack:` prefix** on the case
- Retrieves all conversation history from tagged channels
- **Fallback**: If no tags found, uses default format `#case-CASEID`
- Creates TheHive tasks in "Communication" category with individual task logs for each message
- Downloads and attaches file attachments (images, documents) to task logs
- Chronologically ordered messages with timestamps and usernames
- Prevents duplicate syncing by tracking message timestamps
- Converts Slack user IDs to readable usernames for better readability
- **Multi-channel support**: Syncs multiple channels if multiple `slack:` tags exist

## Preview

![Slack History](./assets/slack-history.png)

![TheHive Slack Sync 1](./assets/thehive-slacksync-1.png)

![TheHive Slack Sync 2](./assets/thehive-slacksync-2.png)

---

## Requirements

- A Slack workspace where you have permissions to create a bot.
- Your bot must be allowed to create channels and invite users.

---

## 1. Create a Slack App & Bot Token

1. Go to [Slack API: Your Apps](https://api.slack.com/apps) and click **"Create New App"**.
2. Choose **From scratch**, name your app, and pick your workspace.
3. Under **Features**, click **OAuth & Permissions**.
4. **Add these OAuth scopes** under **Bot Token Scopes**:

   **For Slack_CreateChannel:**
    - `groups:write` - Manage private channels that your slack app has been added to and create new ones
    - `groups:write.invites` - Invite members to private channels  
    - `groups:write.topic` - Set the description of private channels
    - `groups:read` - View basic information about private channels that your slack app has been added to
    - `users:read.email` - Look up user IDs by email
    - `chat:write` — Send messages as the bot
    
   **For Slack_SyncChannel (additional scopes required):**
    - `channels:history` - Read messages in public channels
    - `groups:history` - View messages and other content in private channels that your slack app has been added to
    - `channels:read` - View basic information about public channels
    - `files:read` - Access file content and info (for downloading attachments)
    - `users:read` - View people in a workspace (for username conversion)
    
   **⚠️ Important for File Downloads:**
   - Your Slack bot must be **added to the channel** where files were shared
   - Files shared before the bot was added may not be downloadable
   - Private files require the bot to have proper permissions

5. **Install the app to your workspace** (top right: "Install to Workspace").
6. After install, **copy your Bot User OAuth Token** (starts with `xoxb-...`).

***Note: don't forget to reinstall your app to workspace to refresh permissions of your BOT.***

---

## 2. Enable and configure the Responders

Log into your Cortex instance, go to Organization > Responders and enable the desired Slack responders with the appropriate configuration & API keys.

---

## Privacy & Security Considerations

### Channel Tagging
When `Slack_CreateChannel` runs, it automatically adds two tags to the case:
- `slack:<channel_name>` - Human-readable channel name
- `slack-id:<channel_id>` - Channel ID for fast direct lookups

This enables `Slack_SyncChannel` to find channels instantly without searching through all workspace channels.

### Syncing Existing Channels
To sync a channel that wasn't created via `Slack_CreateChannel`:
1. Invite the Slack bot to the channel
2. Add `slack:<channel-name>` tag to the case
3. (Optional) Add `slack-id:<channel-id>` for faster lookups
   - Get the ID: right-click channel in Slack → "View channel details" → ID at bottom
4. Run `Slack_SyncChannel`

### Multi-Channel Syncing
`Slack_SyncChannel` will sync **all** channels that have `slack:` tags on the case:
- Each channel creates its own separate task in TheHive
- Partial failures are handled gracefully (some channels may sync, others may fail)
- Failed channels are reported in the responder output

### Access Control
- The bot only searches channels it's a **member of** (security + performance)
- Channels created via `Slack_CreateChannel` automatically include the bot
- Syncing brings Slack conversations into TheHive: ensure case permissions align with channel access
- Private Slack channels synced to non-private TheHive cases may expose sensitive information