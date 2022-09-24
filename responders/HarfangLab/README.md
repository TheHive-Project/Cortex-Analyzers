### HarfangLab responder

This responder allows to interact with a HarfangLab EDR manager for several kinds of use cases, such as: 
  * Isolating/unisolating an endpoint
  * Getting forensics data from an endpoint (running processes, loaded drivers, sessions, prefeteches, services...)
  * Getting raw forensics artifacts (MFT, USN journal, hives...)
  * Hunting in telemetry (processes, network connections, driver loading...) 

The detailed list of HarfangLab's responders is the following:

| Service 				| Applicable object			|
|:-------------------------------------:|:-------------------------------------:|
|HarfangLab_Isolate			| case or alert                         |
|HarfangLab_Unisolate			| case or alert				|
|HarfangLab_KillProcess			| case or alert                         |
|HarfangLab_DumpProcess			| case                                  |
|HarfangLab_GetArtifactAll		| case					|
|HarfangLab_GetArtifactEvtx		| case					|
|HarfangLab_GetArtifactFilesystem	| case					|
|HarfangLab_GetArtifactHives		| case					|
|HarfangLab_GetArtifactLogs		| case					|
|HarfangLab_GetArtifactMFT		| case                                  |
|HarfangLab_GetArtifactPrefetch		| case                                  |
|HarfangLab_GetArtifactRamdump		| case                                  |
|HarfangLab_GetArtifactUSN		| case                                  |
|HarfangLab_GetDrivers			| case                                  |
|HarfangLab_GetNetworkShares		| case                                  |
|HarfangLab_GetPersistence		| case                                  |
|HarfangLab_GetPipes			| case                                  |
|HarfangLab_GetPrefetches		| case                                  |
|HarfangLab_GetProcesses		| case                                  |
|HarfangLab_GetRunKeys			| case                                  |
|HarfangLab_GetScheduledTasks		| case                                  |
|HarfangLab_GetServices			| case                                  |
|HarfangLab_GetSessions			| case                                  |
|HarfangLab_GetStartupFiles		| case                                  |
|HarfangLab_GetWMI			| case                                  |
|HarfangLab_SearchDestinationIP		| case_artifact / ip                    |
|HarfangLab_SearchDriverByFileName	| case_artifact / filename              |
|HarfangLab_SearchDriverByHash		| case_artifact / hash                  |
|HarfangLab_SearchHash			| case_artifact / hash                  |
|HarfangLab_SearchSourceIP		| case_artifact / ip                    |
|HarfangLab_GetBinary			| case_artifact / hash                  |


