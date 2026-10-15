// SPDX-License-Identifier: GPL-2.0-only
// Keep the diagnostic observation graph out of ordinary status and AP workers.
import { planning_observation } from './radio_planning_runtime.uc';
return { observe: planning_observation };
