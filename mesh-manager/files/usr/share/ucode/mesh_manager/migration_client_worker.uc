// SPDX-License-Identifier: GPL-2.0-only
// Keep migration parsing and authority transfer out of the ordinary AP graph.
'use strict';
import {migration_client} from './migration_client.uc';
// Reuse the AP's existing adapters. Importing another agent_local/runtime graph
// in this lazy worker would keep a second complete transaction VM resident.
return migration_client;
