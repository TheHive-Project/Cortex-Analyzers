### HarfangLab responder

This responder allows to interact with a HarfangLab EDR manager for several kinds of use cases, such as: 
  * Isolating/unisolating an endpoint
  * Getting forensics data from an endpoint (running processes, loaded drivers, sessions, prefeteches, services...)
  * Getting raw forensics artifacts (MFT, USN journal, hives...)
  * Hunting in telemetry (processes, network connections, driver loading...) 

The detailed list of HarfangLab's responders is the following:

| Service                               | Applicable object                     | Requirement                           | Description                                                                                   |
|:-------------------------------------:|:-------------------------------------:|:--------------------------------------|:---------------------------------------------------------------------------------------|
|HarfangLab_Isolate                     | case or alert                         | **Agent identifier** custom field.    | Allows to isolate an endpoint (add a HarfangLab:isolated tag to a case when done).     |
|HarfangLab_Unisolate                   | case or alert                         | **Agent identifier** custom field.    | Allows to unisolate and endpoint (add a HarfangLab:unisolated tag to a case when done).|
|HarfangLab_KillProcess                 | case or alert                         | **Process / Unique identifier** custom field.| Allows to kill a process.                                                       |
|HarfangLab_DumpProcess                 | case                                  | **Process / Unique identifier** custom field.| Allows to dump a process memory.                                                |
|HarfangLab_GetArtifactAll              | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with all artifacts (MFT, USN, EVTX, etc.).               |
|HarfangLab_GetArtifactEvtx             | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with Evtx artifact (Windows).                            |
|HarfangLab_GetArtifactFilesystem       | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with file system artifact (Linux).                       |
|HarfangLab_GetArtifactHives            | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with Hives artifact (Windows).                           |
|HarfangLab_GetArtifactLogs             | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with Logs artifact (Linux).                              |
|HarfangLab_GetArtifactMFT              | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with MFT artifact (Windows).                             |
|HarfangLab_GetArtifactPrefetch         | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with Prefetch artifact (Windows).                        |
|HarfangLab_GetArtifactRamdump          | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with a RAM dump artifact.                                |
|HarfangLab_GetArtifactUSN              | case                                  | **Agent identifier** custom field.    | Allows to get an archive file with USN journal artifact.                               |
|HarfangLab_GetDrivers                  | case                                  | **Agent identifier** custom field.    | Allows to get the list of loaded drivers.                                              |
|HarfangLab_GetNetworkShares            | case                                  | **Agent identifier** custom field.    | Allows to get the list of network shares.                                              |
|HarfangLab_GetPersistence              | case                                  | **Agent identifier** custom field.    | Allows to get the list of persistence items (Linux).                                   |
|HarfangLab_GetPipes                    | case                                  | **Agent identifier** custom field.    | Allows to get the list of pipes.                                                       |
|HarfangLab_GetPrefetches               | case                                  | **Agent identifier** custom field.    | Allows to get the list of prefetches.                                                  |
|HarfangLab_GetProcesses                | case                                  | **Agent identifier** custom field.    | Allows to get the list of running processes and their associated information (open sockets, handles, threads...).        |
|HarfangLab_GetRunKeys                  | case                                  | **Agent identifier** custom field.    | Allows to get the list of RUN keys.                                                    |
|HarfangLab_GetScheduledTasks           | case                                  | **Agent identifier** custom field.    | Allows to get the list of scheduled tasks.                                             |
|HarfangLab_GetServices                 | case                                  | **Agent identifier** custom field.    | Allows to get the list of services.                                                    |
|HarfangLab_GetSessions                 | case                                  | **Agent identifier** custom field.    | Allows to get the list of sessions.                                                    |
|HarfangLab_GetStartupFiles             | case                                  | **Agent identifier** custom field.    | Allows to get the list of startup files.                                               |
|HarfangLab_GetWMI                      | case                                  | **Agent identifier** custom field.    | Allows to get the list of WMI items.                                                   |
|HarfangLab_SearchDestinationIP         | case_artifact / ip                    | Case artifact with **ip** observable. | Allows to search the destination IP in the whole telemetry.                            |
|HarfangLab_SearchDriverByFileName      | case_artifact / filename              | Case artifact with **filename** observable. | Allows to search the driver filename in the whole telemetry.                     |
|HarfangLab_SearchDriverByHash          | case_artifact / hash                  | Case artifact with **hash** observable. | Allows to search the driver hash in the whole telemetry.                             |
|HarfangLab_SearchHash                  | case_artifact / hash                  | Case artifact with **hash** observable. | Allows to search the file hash in the whole telemetry.                               |
|HarfangLab_SearchSourceIP              | case_artifact / ip                    | Case artifact with **ip** observable. | Allows to search the source IP in the whole telemetry.                                 |
|HarfangLab_GetBinary                   | case_artifact / hash                  | Case artifact with **hash** observable. | Allows to search the file hash in the whole telemetry.                               |


