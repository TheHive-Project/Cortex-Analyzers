# Change Log

## [2.7.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.7.0) (2020-05-14)

[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.6.0...2.7.0)

**Implemented enhancements:**

- \[discussion\] Mispwarninglist analyzer speed issue and proposed improvement  [\#731](https://github.com/TheHive-Project/Cortex-Analyzers/issues/731)
- Improvement: extract IOCs from EmlParser [\#710](https://github.com/TheHive-Project/Cortex-Analyzers/issues/710)
- \[FR\] Yeti Analyzer - SSL error with self signed certificate [\#468](https://github.com/TheHive-Project/Cortex-Analyzers/issues/468)
- BlueCoat Malware Analysis Sandbox Analyzer  [\#145](https://github.com/TheHive-Project/Cortex-Analyzers/issues/145)

**Fixed bugs:**

- \[Bug\] MaxMind [\#752](https://github.com/TheHive-Project/Cortex-Analyzers/issues/752)
- \[Bug\] EmailRep [\#750](https://github.com/TheHive-Project/Cortex-Analyzers/issues/750)
- \[Bug\] Shodan Analyzer: Inconsistent Key References [\#748](https://github.com/TheHive-Project/Cortex-Analyzers/issues/748)
- json.dump \n and \" [\#743](https://github.com/TheHive-Project/Cortex-Analyzers/issues/743)
- \[Bug\] Yeti Analyzer docker images pip installing pyeti [\#708](https://github.com/TheHive-Project/Cortex-Analyzers/issues/708)
- \[Bug\] FireHOLBlocklists No such file or directory [\#707](https://github.com/TheHive-Project/Cortex-Analyzers/issues/707)
- \[Bug\] DNSDB Analyzer Python 3 incompatability [\#613](https://github.com/TheHive-Project/Cortex-Analyzers/issues/613)
- \[Bug\] Worker cannot be run [\#595](https://github.com/TheHive-Project/Cortex-Analyzers/issues/595)
- \[Bug\] Crt\_sh\_Transparency\_Logs\_1\_0 - No JSON object could be decoded [\#594](https://github.com/TheHive-Project/Cortex-Analyzers/issues/594)
- \[Bug\] TheHive isn't showing error messages from responders [\#429](https://github.com/TheHive-Project/Cortex-Analyzers/issues/429)

**Closed issues:**

- New Analyzer:  ANY.RUN [\#734](https://github.com/TheHive-Project/Cortex-Analyzers/issues/734)
- New Analyzer: OpenCTI [\#723](https://github.com/TheHive-Project/Cortex-Analyzers/issues/723)
- New Analyzer: MalwareBazaar [\#722](https://github.com/TheHive-Project/Cortex-Analyzers/issues/722)
- New analyzer : Google Vision API  [\#298](https://github.com/TheHive-Project/Cortex-Analyzers/issues/298)

**Merged pull requests:**

- added key to emailrep [\#751](https://github.com/TheHive-Project/Cortex-Analyzers/pull/751) ([dadokkio](https://github.com/dadokkio))
- fix infos\_domain key in shodan [\#749](https://github.com/TheHive-Project/Cortex-Analyzers/pull/749) ([dadokkio](https://github.com/dadokkio))
- fix on python3 compatibility for \#696 [\#745](https://github.com/TheHive-Project/Cortex-Analyzers/pull/745) ([dadokkio](https://github.com/dadokkio))
- fix multuple yeti issues [\#740](https://github.com/TheHive-Project/Cortex-Analyzers/pull/740) ([dadokkio](https://github.com/dadokkio))
- add analyzer for any.run sandbox [\#735](https://github.com/TheHive-Project/Cortex-Analyzers/pull/735) ([dadokkio](https://github.com/dadokkio))
- Postgres as backend for mispwarninglist [\#732](https://github.com/TheHive-Project/Cortex-Analyzers/pull/732) ([dadokkio](https://github.com/dadokkio))
- Fix bug emlparser when 'content-type' string in mail is in lower case [\#730](https://github.com/TheHive-Project/Cortex-Analyzers/pull/730) ([TofBaasken](https://github.com/TofBaasken))
- malwarebazaar hash search [\#728](https://github.com/TheHive-Project/Cortex-Analyzers/pull/728) ([dadokkio](https://github.com/dadokkio))
- Add OpenCTI Analyzer v1 [\#725](https://github.com/TheHive-Project/Cortex-Analyzers/pull/725) ([amr-cossi](https://github.com/amr-cossi))

## [2.6.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.6.0) (2020-03-25)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.5.0...2.6.0)

**Implemented enhancements:**

- New Analyzer: Mnemonic PDNS \(Public & Closed\) [\#255](https://github.com/TheHive-Project/Cortex-Analyzers/issues/255)
- \[Bug\] AbuseIPDB analyzer returns error [\#701](https://github.com/TheHive-Project/Cortex-Analyzers/issues/701)
- Update UmbrellaBlacklister [\#547](https://github.com/TheHive-Project/Cortex-Analyzers/pull/547) ([arnydo](https://github.com/arnydo))
- Fix - updated cortexutil Extractor return keys [\#538](https://github.com/TheHive-Project/Cortex-Analyzers/pull/538) ([dadokkio](https://github.com/dadokkio))
- Issue \#521 Fix - Talos Analyzer No Longer Works [\#522](https://github.com/TheHive-Project/Cortex-Analyzers/pull/522) ([colin-stubbs](https://github.com/colin-stubbs))
- \[ThreatCrowd \] Fixing Unexpected Error: get\(\) takes exactly 1 argument \(2 given\) [\#518](https://github.com/TheHive-Project/Cortex-Analyzers/pull/518) ([presianbg](https://github.com/presianbg))

**Fixed bugs:**

- \[Bug\] Importing Templates of Analyzers in Hive [\#704](https://github.com/TheHive-Project/Cortex-Analyzers/issues/704)
- \[Bug\] VMRay Returns Error [\#520](https://github.com/TheHive-Project/Cortex-Analyzers/issues/520)
- \[Bug\] FileInfo does not run Oletools submodule for a doc [\#705](https://github.com/TheHive-Project/Cortex-Analyzers/issues/705)
- \[Bug\] Investigate Analyzer Broken [\#703](https://github.com/TheHive-Project/Cortex-Analyzers/issues/703)
- \\[Bug\\] AbuseIPDB analyzer returns error [\#701](https://github.com/TheHive-Project/Cortex-Analyzers/issues/701)
- Analyzers missing cortexutils in requirements.txt [\#695](https://github.com/TheHive-Project/Cortex-Analyzers/issues/695)
- \[Bug\] abuselpdb stop stupport APIv1 [\#618](https://github.com/TheHive-Project/Cortex-Analyzers/issues/618)
- \[Bug\] All Onyphe analyzer return "Invalid output" [\#591](https://github.com/TheHive-Project/Cortex-Analyzers/issues/591)
- \[Bug\] Mailer 1\_0 [\#573](https://github.com/TheHive-Project/Cortex-Analyzers/issues/573)

**Closed issues:**

- Responder Cisco AMP for Endpoints [\#593](https://github.com/TheHive-Project/Cortex-Analyzers/issues/593)
- Analyzer Cisco Threat Response  [\#592](https://github.com/TheHive-Project/Cortex-Analyzers/issues/592)
- MISP-Warninglists Analyzer Outdated [\#569](https://github.com/TheHive-Project/Cortex-Analyzers/issues/569)
- Invalid requirements in responder FalconCustomIOC requirements.txt [\#509](https://github.com/TheHive-Project/Cortex-Analyzers/issues/509)
- ClamAV New analyzer [\#311](https://github.com/TheHive-Project/Cortex-Analyzers/issues/311)
- CISCO AMP Sandbox Analyzer [\#146](https://github.com/TheHive-Project/Cortex-Analyzers/issues/146)
- Intezer Community analyzer [\#504](https://github.com/TheHive-Project/Cortex-Analyzers/issues/504)
- Analyzer Feature: URLScan.io "Scan" Service [\#405](https://github.com/TheHive-Project/Cortex-Analyzers/issues/405)
- New Analyzer: NSRL check [\#391](https://github.com/TheHive-Project/Cortex-Analyzers/issues/391)

**Merged pull requests:**

- abuseipdb update api to v2 [\#719](https://github.com/TheHive-Project/Cortex-Analyzers/pull/719) ([dadokkio](https://github.com/dadokkio))
- Revert "\[ThreatCrowd \] Fixing Unexpected Error: get\(\) takes exactly 1 argument \(2 given\)" [\#716](https://github.com/TheHive-Project/Cortex-Analyzers/pull/716) ([dadokkio](https://github.com/dadokkio))
- Revert "added IntezerCommunity analyzer" [\#713](https://github.com/TheHive-Project/Cortex-Analyzers/pull/713) ([garanews](https://github.com/garanews))
- cortexutils in all requirements.txt [\#711](https://github.com/TheHive-Project/Cortex-Analyzers/pull/711) ([garanews](https://github.com/garanews))
- fqdn  support for Url haus [\#706](https://github.com/TheHive-Project/Cortex-Analyzers/pull/706) ([garanews](https://github.com/garanews))
- Revert 726 revert 714 dt config clean up [\#727](https://github.com/TheHive-Project/Cortex-Analyzers/pull/727) ([jeromeleonard](https://github.com/jeromeleonard))
- Revert "DomainToolsIris config cleanup" [\#726](https://github.com/TheHive-Project/Cortex-Analyzers/pull/726) ([jeromeleonard](https://github.com/jeromeleonard))
- Revert "Bumped Investigate version" [\#721](https://github.com/TheHive-Project/Cortex-Analyzers/pull/721) ([jeromeleonard](https://github.com/jeromeleonard))
- Bumped Investigate version [\#718](https://github.com/TheHive-Project/Cortex-Analyzers/pull/718) ([garanews](https://github.com/garanews))
- fix some code for python3 compatibility [\#717](https://github.com/TheHive-Project/Cortex-Analyzers/pull/717) ([dadokkio](https://github.com/dadokkio))
- DomainToolsIris config cleanup [\#714](https://github.com/TheHive-Project/Cortex-Analyzers/pull/714) ([ChuckWoodraska](https://github.com/ChuckWoodraska))
- Feature/nsrl [\#712](https://github.com/TheHive-Project/Cortex-Analyzers/pull/712) ([dadokkio](https://github.com/dadokkio))
- Added url scan feature [\#709](https://github.com/TheHive-Project/Cortex-Analyzers/pull/709) ([dadokkio](https://github.com/dadokkio))
-  DomainTools Iris - Malicious Tags Responder [\#588](https://github.com/TheHive-Project/Cortex-Analyzers/pull/588) ([ChuckWoodraska](https://github.com/ChuckWoodraska))
- DomainTools Iris - Investigate Analyzer [\#572](https://github.com/TheHive-Project/Cortex-Analyzers/pull/572) ([ChuckWoodraska](https://github.com/ChuckWoodraska))
- added IntezerCommunity analyzer [\#505](https://github.com/TheHive-Project/Cortex-Analyzers/pull/505) ([mlodic](https://github.com/mlodic))

## [2.5.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.5.0) (2020-02-24)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.4.1...2.5.0)

**Fixed bugs:**

- \[Bug\] Umbrella Investigate report error message 'Unknown Investigate service or invalid data type' [\#698](https://github.com/TheHive-Project/Cortex-Analyzers/issues/698)
- Virusshare analyzer: suggesting another way to retrieve hash file names [\#359](https://github.com/TheHive-Project/Cortex-Analyzers/issues/359)
- Cuckoo analyzer sometimes failes [\#114](https://github.com/TheHive-Project/Cortex-Analyzers/issues/114)

**Closed issues:**

- IPVoid IP reputation API  [\#454](https://github.com/TheHive-Project/Cortex-Analyzers/issues/454)

**Merged pull requests:**

- Cisco Threat Response Analyzer [\#598](https://github.com/TheHive-Project/Cortex-Analyzers/pull/598) ([maugertg](https://github.com/maugertg))
- Cisco Threat Grid Analyzer [\#597](https://github.com/TheHive-Project/Cortex-Analyzers/pull/597) ([maugertg](https://github.com/maugertg))
- Cisco AMP for Endpoints Responder [\#596](https://github.com/TheHive-Project/Cortex-Analyzers/pull/596) ([maugertg](https://github.com/maugertg))
- Added IPVoid IP reputation API analyzer  [\#455](https://github.com/TheHive-Project/Cortex-Analyzers/pull/455) ([jdsnape](https://github.com/jdsnape))
- Redmine responder [\#342](https://github.com/TheHive-Project/Cortex-Analyzers/pull/342) ([srilumpa](https://github.com/srilumpa))

## [2.4.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.4.1) (2020-02-11)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.4.0...2.4.1)

**Implemented enhancements:**

- Rename AUTOFOCUS analyzers to Autofocus [\#616](https://github.com/TheHive-Project/Cortex-Analyzers/issues/616)

**Fixed bugs:**

- \[Bug\] MaxMind\_GeoIP\_3\_0 [\#564](https://github.com/TheHive-Project/Cortex-Analyzers/issues/564)
- Error when building docker image for MalwareClustering [\#620](https://github.com/TheHive-Project/Cortex-Analyzers/issues/620)
- Abuse Finder not working with docker after force usage of python3 [\#619](https://github.com/TheHive-Project/Cortex-Analyzers/issues/619)
- \[Bug\] Permission Denied on Analyzer Execution [\#614](https://github.com/TheHive-Project/Cortex-Analyzers/issues/614)
- \[Bug\] VirusTotal script elif statement ends with semicolon typo [\#610](https://github.com/TheHive-Project/Cortex-Analyzers/issues/610)

**Closed issues:**

- Emailrep.io analyzer [\#466](https://github.com/TheHive-Project/Cortex-Analyzers/issues/466)
- IPinfo analyzer [\#462](https://github.com/TheHive-Project/Cortex-Analyzers/issues/462)
- Maltiverse Analyzer [\#440](https://github.com/TheHive-Project/Cortex-Analyzers/issues/440)
- \[FR\] Spamhaus DBL Analyzer [\#436](https://github.com/TheHive-Project/Cortex-Analyzers/issues/436)
- New Analyzer: SoltraEdge [\#264](https://github.com/TheHive-Project/Cortex-Analyzers/issues/264)

## [2.4.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.4.0) (2020-02-10)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.3.0...2.4.0)

**Implemented enhancements:**

- Force python3 in all analyzers [\#361](https://github.com/TheHive-Project/Cortex-Analyzers/issues/361)
- fix: python3 compatibility for otxquery analyzer [\#590](https://github.com/TheHive-Project/Cortex-Analyzers/pull/590) ([iwitz](https://github.com/iwitz))
- fix: OTXQuery Python3 compatibility [\#567](https://github.com/TheHive-Project/Cortex-Analyzers/pull/567) ([iwitz](https://github.com/iwitz))
- Updating GreyNoise analyzer to use v2 API  [\#562](https://github.com/TheHive-Project/Cortex-Analyzers/pull/562) ([shortstack](https://github.com/shortstack))
- fix for Shodan [\#558](https://github.com/TheHive-Project/Cortex-Analyzers/pull/558) ([malwareowl](https://github.com/malwareowl))
- fix for threatcrowd [\#557](https://github.com/TheHive-Project/Cortex-Analyzers/pull/557) ([malwareowl](https://github.com/malwareowl))
- fix for virus total [\#555](https://github.com/TheHive-Project/Cortex-Analyzers/pull/555) ([malwareowl](https://github.com/malwareowl))
- Fix for the Abuse\_Finder and Fortiguard [\#541](https://github.com/TheHive-Project/Cortex-Analyzers/pull/541) ([phpsystems](https://github.com/phpsystems))
- fix some typo [\#537](https://github.com/TheHive-Project/Cortex-Analyzers/pull/537) ([garanews](https://github.com/garanews))
- PassiveTotal Analyzer: Added support for additional data sets [\#497](https://github.com/TheHive-Project/Cortex-Analyzers/pull/497) ([9b](https://github.com/9b))
- Abuse\_Finder : Add support to Python3.6 [\#469](https://github.com/TheHive-Project/Cortex-Analyzers/pull/469) ([LetMeR00t](https://github.com/LetMeR00t))

**Fixed bugs:**

- \[Bug\] SSL verification failing for majority of analyzers. [\#605](https://github.com/TheHive-Project/Cortex-Analyzers/issues/605)
- \[Bug\] JoeSandbox analyzer fails if terms and conditions are not accepted [\#565](https://github.com/TheHive-Project/Cortex-Analyzers/issues/565)
- \[Bug\] MISP 2.0 analyzer search crashes the MISP instance [\#602](https://github.com/TheHive-Project/Cortex-Analyzers/issues/602)
- OTXQuery Error - No module named requests [\#574](https://github.com/TheHive-Project/Cortex-Analyzers/issues/574)
- \[Bug\] Abuse\_Finder\_2\_0 [\#566](https://github.com/TheHive-Project/Cortex-Analyzers/issues/566)

**Closed issues:**

- Cisco Umbrella Investigate Analyzer \[FR\] [\#583](https://github.com/TheHive-Project/Cortex-Analyzers/issues/583)
- Add Wazuh Responder [\#578](https://github.com/TheHive-Project/Cortex-Analyzers/issues/578)
- \[FR\] Palo Alto Minemeld Responder [\#577](https://github.com/TheHive-Project/Cortex-Analyzers/issues/577)
- \[FR\] Team Cymru Malware Hash Registry Analyzer [\#576](https://github.com/TheHive-Project/Cortex-Analyzers/issues/576)
- New Responder: KnowBe4 \(WIP\) [\#548](https://github.com/TheHive-Project/Cortex-Analyzers/issues/548)
- \[FR\] Analyzer for PaloAltoNetworks Autofocus service [\#472](https://github.com/TheHive-Project/Cortex-Analyzers/issues/472)

**Merged pull requests:**

-  DomainTools Iris - Risky DNS Responder [\#587](https://github.com/TheHive-Project/Cortex-Analyzers/pull/587) ([ChuckWoodraska](https://github.com/ChuckWoodraska))
- DomainTools Iris - Pivot Analyzer [\#586](https://github.com/TheHive-Project/Cortex-Analyzers/pull/586) ([ChuckWoodraska](https://github.com/ChuckWoodraska))
- Add Spamhaus DBL analyzer [\#585](https://github.com/TheHive-Project/Cortex-Analyzers/pull/585) ([weslambert](https://github.com/weslambert))
- Add Wazuh responder [\#582](https://github.com/TheHive-Project/Cortex-Analyzers/pull/582) ([weslambert](https://github.com/weslambert))
- Add Palo Alto Minemeld Responder [\#581](https://github.com/TheHive-Project/Cortex-Analyzers/pull/581) ([weslambert](https://github.com/weslambert))
- Add TeamCymruMHR Analyzer [\#580](https://github.com/TheHive-Project/Cortex-Analyzers/pull/580) ([weslambert](https://github.com/weslambert))
- Update EmailRep analyzer [\#575](https://github.com/TheHive-Project/Cortex-Analyzers/pull/575) ([ninoseki](https://github.com/ninoseki))
- New Responder KnowBe4 [\#549](https://github.com/TheHive-Project/Cortex-Analyzers/pull/549) ([arnydo](https://github.com/arnydo))
- Autofocus analyzer v1 [\#473](https://github.com/TheHive-Project/Cortex-Analyzers/pull/473) ([amr-cossi](https://github.com/amr-cossi))
- add Emailrep analyzer [\#467](https://github.com/TheHive-Project/Cortex-Analyzers/pull/467) ([ninoseki](https://github.com/ninoseki))
- Add IPinfo analyzer [\#463](https://github.com/TheHive-Project/Cortex-Analyzers/pull/463) ([ninoseki](https://github.com/ninoseki))
- remove builtin modules from requirements.txt [\#457](https://github.com/TheHive-Project/Cortex-Analyzers/pull/457) ([ag-michael](https://github.com/ag-michael))
- Malware clustering [\#351](https://github.com/TheHive-Project/Cortex-Analyzers/pull/351) ([garanews](https://github.com/garanews))

## [2.3.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.3.0) (2019-11-28)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.2.0...2.3.0)

**Implemented enhancements:**

- fix when hash not found [\#485](https://github.com/TheHive-Project/Cortex-Analyzers/pull/485) ([garanews](https://github.com/garanews))
- fixed Talos analyzer [\#546](https://github.com/TheHive-Project/Cortex-Analyzers/pull/546) ([0xmilkmix](https://github.com/0xmilkmix))
- removed python builtins from requirements.txt [\#517](https://github.com/TheHive-Project/Cortex-Analyzers/pull/517) ([github-pba](https://github.com/github-pba))
- Support for Cuckoo 2.0.7 and custom CA [\#514](https://github.com/TheHive-Project/Cortex-Analyzers/pull/514) ([1earch](https://github.com/1earch))
- updated joesandbox analyzer [\#512](https://github.com/TheHive-Project/Cortex-Analyzers/pull/512) ([garanews](https://github.com/garanews))

**Fixed bugs:**

- Old non-existent analysers showing in Cortex \[Bug\] [\#553](https://github.com/TheHive-Project/Cortex-Analyzers/issues/553)
- \[Bug\] Custom responder not working after upgrade to cortex 3 [\#542](https://github.com/TheHive-Project/Cortex-Analyzers/issues/542)
- \[Bug\] ThreatCrowd analyzer not respecting Max TLP value [\#527](https://github.com/TheHive-Project/Cortex-Analyzers/issues/527)
- \[Bug\]Missing baseConfig in two Analyzsers [\#508](https://github.com/TheHive-Project/Cortex-Analyzers/issues/508)
- \[Bug\] MISP analyzer does not connect to MISP [\#480](https://github.com/TheHive-Project/Cortex-Analyzers/issues/480)
- \[Bug\] Missing module dependencies on responders [\#561](https://github.com/TheHive-Project/Cortex-Analyzers/issues/561)
- \[Bug\] [\#552](https://github.com/TheHive-Project/Cortex-Analyzers/issues/552)
- \[Bug\] Requests module is missing in PhishTank checkurl analyzer docker image [\#551](https://github.com/TheHive-Project/Cortex-Analyzers/issues/551)
- Add mime types of encrypted documents [\#550](https://github.com/TheHive-Project/Cortex-Analyzers/issues/550)
- \[Bug\] Cuckoo Sandbox 2.0.7 [\#544](https://github.com/TheHive-Project/Cortex-Analyzers/issues/544)
- \[Bug\] Docker build fails due to spaces in some responders [\#540](https://github.com/TheHive-Project/Cortex-Analyzers/issues/540)
- Talos Analyzer No Longer Works [\#521](https://github.com/TheHive-Project/Cortex-Analyzers/issues/521)
- \[Bug\] Fortiguard: Category parsing does not handle "-" [\#493](https://github.com/TheHive-Project/Cortex-Analyzers/issues/493)
- fix when hash not found [\#485](https://github.com/TheHive-Project/Cortex-Analyzers/pull/485) ([garanews](https://github.com/garanews))
- Fix category parsing forom Fortiguard URLCategory [\#494](https://github.com/TheHive-Project/Cortex-Analyzers/pull/494) ([srilumpa](https://github.com/srilumpa))

**Closed issues:**

- MaxMind Analyzer: Use commercial databases with geoipupdate [\#474](https://github.com/TheHive-Project/Cortex-Analyzers/issues/474)

**Merged pull requests:**

- Metadefender analyzer [\#510](https://github.com/TheHive-Project/Cortex-Analyzers/pull/510) ([garanews](https://github.com/garanews))

## [2.2.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.2.0) (2019-10-01)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.8...2.2.0)

**Implemented enhancements:**

- \[FR\] Manage encrypted Office documents in FileInfo [\#533](https://github.com/TheHive-Project/Cortex-Analyzers/issues/533)
- \[FR\] Use HEAD instead of GET in UnshortenLink [\#506](https://github.com/TheHive-Project/Cortex-Analyzers/issues/506)
- Responder: Block a "domain" observable via BIND RPZ DDNS update [\#435](https://github.com/TheHive-Project/Cortex-Analyzers/issues/435)

**Fixed bugs:**

- \[Bug\] VirusTotal\_GetReport does not work anymore [\#519](https://github.com/TheHive-Project/Cortex-Analyzers/issues/519)
- \[Bug\] Cortex Analyzers Invalid output [\#515](https://github.com/TheHive-Project/Cortex-Analyzers/issues/515)
- \[Bug\] FileInfo crashes with some PDF  [\#536](https://github.com/TheHive-Project/Cortex-Analyzers/issues/536)
- \[Bug\] Hybrid Analysis getReport fails with observable with datatype = file [\#535](https://github.com/TheHive-Project/Cortex-Analyzers/issues/535)
- \[Bug\] HIBP Analyser no longer works [\#524](https://github.com/TheHive-Project/Cortex-Analyzers/issues/524)
- \[Misc\] Remove Cymon analyzer [\#489](https://github.com/TheHive-Project/Cortex-Analyzers/issues/489)
- \[Bug\] Umbrella\_Report\_1\_0 analyzer returning Invalid output [\#459](https://github.com/TheHive-Project/Cortex-Analyzers/issues/459)
- Encoding error in Shodan results [\#322](https://github.com/TheHive-Project/Cortex-Analyzers/issues/322)
- \[BugFix\] HIBP Analyser no longer works [\#525](https://github.com/TheHive-Project/Cortex-Analyzers/pull/525) ([jonashergenhahn](https://github.com/jonashergenhahn))

**Closed issues:**

- \[FR\] Responder "request for takedown" in Zerofox [\#532](https://github.com/TheHive-Project/Cortex-Analyzers/issues/532)
- \[FR\] Responder "Close Alert" for Zerofox [\#531](https://github.com/TheHive-Project/Cortex-Analyzers/issues/531)
- Responder QRadarAutoClose [\#441](https://github.com/TheHive-Project/Cortex-Analyzers/issues/441)

**Merged pull requests:**

- Responder QRadarAutoClose [\#460](https://github.com/TheHive-Project/Cortex-Analyzers/pull/460) ([cyberpescadito](https://github.com/cyberpescadito))
- Add responder DNS-RPZ \(issue \#435\) [\#447](https://github.com/TheHive-Project/Cortex-Analyzers/pull/447) ([mhexp](https://github.com/mhexp))
- New analyser : Google Vision API [\#297](https://github.com/TheHive-Project/Cortex-Analyzers/pull/297) ([0xswitch](https://github.com/0xswitch))

## [2.1.8](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.8) (2019-07-12)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.7...2.1.8)

**Fixed bugs:**

- \[Bug\] PassiveTotal SSL Certificate History analyzer always report at least one record, even if there isn't one [\#513](https://github.com/TheHive-Project/Cortex-Analyzers/issues/513)

## [2.1.7](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.7) (2019-07-10)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.6...2.1.7)

**Implemented enhancements:**

- Analyzer Template Check-Up [\#213](https://github.com/TheHive-Project/Cortex-Analyzers/issues/213)

**Fixed bugs:**

- \[Bug\] FortiGuard cannot parse response content [\#491](https://github.com/TheHive-Project/Cortex-Analyzers/issues/491)
- Threatcrowd, TorBlutmagie, TorProject not displayed [\#414](https://github.com/TheHive-Project/Cortex-Analyzers/issues/414)
- OTXQuery\_2\_0 Error when submitting IP address  [\#363](https://github.com/TheHive-Project/Cortex-Analyzers/issues/363)

**Closed issues:**

- New analyzer: Talos Reputation [\#426](https://github.com/TheHive-Project/Cortex-Analyzers/issues/426)

## [2.1.6](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.6) (2019-06-21)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.5...2.1.6)

**Fixed bugs:**

- Missing request lib in the docker of  Fortiguard analyzer [\#503](https://github.com/TheHive-Project/Cortex-Analyzers/issues/503)

## [2.1.5](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.5) (2019-06-20)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.4...2.1.5)

**Fixed bugs:**

- Docker for EmlParser is not working, python-magic is missing [\#502](https://github.com/TheHive-Project/Cortex-Analyzers/issues/502)

## [2.1.4](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.4) (2019-06-20)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.3...2.1.4)

**Fixed bugs:**

- TalosReputation : not cortexutils in requirements.txt [\#501](https://github.com/TheHive-Project/Cortex-Analyzers/issues/501)

## [2.1.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.3) (2019-06-17)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.2...2.1.3)

**Fixed bugs:**

- Problem with iocp requirement [\#500](https://github.com/TheHive-Project/Cortex-Analyzers/issues/500)

## [2.1.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.2) (2019-06-16)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.1...2.1.2)

## [2.1.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.1) (2019-06-16)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.1.0...2.1.1)

## [2.1.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.1.0) (2019-06-09)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.0.1...2.1.0)

**Implemented enhancements:**

- FileInfo : extract URL from documents like PDF or Office [\#465](https://github.com/TheHive-Project/Cortex-Analyzers/issues/465)
- Use up to date msg-Extract lib  in FileInfo [\#464](https://github.com/TheHive-Project/Cortex-Analyzers/issues/464)
- \[FR\] Updated crt.sh Analyzer [\#438](https://github.com/TheHive-Project/Cortex-Analyzers/issues/438)
- Use req.text instead of req.content [\#492](https://github.com/TheHive-Project/Cortex-Analyzers/pull/492) ([srilumpa](https://github.com/srilumpa))
- remove extra slash [\#488](https://github.com/TheHive-Project/Cortex-Analyzers/pull/488) ([garanews](https://github.com/garanews))
- EmlParser - Fixed headers and displayTo  [\#486](https://github.com/TheHive-Project/Cortex-Analyzers/pull/486) ([mgabriel-silva](https://github.com/mgabriel-silva))
- Crtsh updates [\#432](https://github.com/TheHive-Project/Cortex-Analyzers/pull/432) ([kx499](https://github.com/kx499))

**Fixed bugs:**

- \[Bug\] IBM X-Force Analyzer adds an extra slash which prevents it from running correctly [\#487](https://github.com/TheHive-Project/Cortex-Analyzers/issues/487)
- Cuckoo Sandbox Analyzer error [\#458](https://github.com/TheHive-Project/Cortex-Analyzers/issues/458)
- \[Bug\] EmlParser has incomplete header [\#484](https://github.com/TheHive-Project/Cortex-Analyzers/issues/484)
- \[Bug\] OpenXML files detected as zip but ignored by Oletools. [\#475](https://github.com/TheHive-Project/Cortex-Analyzers/issues/475)
- \[Bug\] Malwares\_GetReport\_1\_0 [\#470](https://github.com/TheHive-Project/Cortex-Analyzers/issues/470)
- Use req.text instead of req.content [\#492](https://github.com/TheHive-Project/Cortex-Analyzers/pull/492) ([srilumpa](https://github.com/srilumpa))
- Umbrella analyzer: query\_limit: error if no data provided [\#479](https://github.com/TheHive-Project/Cortex-Analyzers/pull/479) ([siisar](https://github.com/siisar))
- remove extra slash [\#488](https://github.com/TheHive-Project/Cortex-Analyzers/pull/488) ([garanews](https://github.com/garanews))
- EmlParser - Fixed headers and displayTo  [\#486](https://github.com/TheHive-Project/Cortex-Analyzers/pull/486) ([mgabriel-silva](https://github.com/mgabriel-silva))
- Use VirusTotal with python3  \(issue \#361\) [\#446](https://github.com/TheHive-Project/Cortex-Analyzers/pull/446) ([Nergie](https://github.com/Nergie))
- Fix emlParser crash [\#439](https://github.com/TheHive-Project/Cortex-Analyzers/pull/439) ([agix](https://github.com/agix))

**Closed issues:**

- "errorMessage": "Missing dataType field" [\#481](https://github.com/TheHive-Project/Cortex-Analyzers/issues/481)
- Hashdd\_Detail\_1\_0 throwing error [\#461](https://github.com/TheHive-Project/Cortex-Analyzers/issues/461)
-   "errorMessage": "Invalid output\n" on Mail Responder [\#452](https://github.com/TheHive-Project/Cortex-Analyzers/issues/452)

**Merged pull requests:**

- added custom Dns sinkholed ip [\#482](https://github.com/TheHive-Project/Cortex-Analyzers/pull/482) ([garanews](https://github.com/garanews))
- yeti api key [\#478](https://github.com/TheHive-Project/Cortex-Analyzers/pull/478) ([siisar](https://github.com/siisar))
- Possibility to use a Yeti apikey. [\#477](https://github.com/TheHive-Project/Cortex-Analyzers/pull/477) ([siisar](https://github.com/siisar))
- Utility to make running an Analyzer locally easier, helpful in development [\#471](https://github.com/TheHive-Project/Cortex-Analyzers/pull/471) ([ndejong](https://github.com/ndejong))
- DNSSinkhole analyzer [\#434](https://github.com/TheHive-Project/Cortex-Analyzers/pull/434) ([garanews](https://github.com/garanews))
- New analyzer: Talos Reputation [\#427](https://github.com/TheHive-Project/Cortex-Analyzers/pull/427) ([mgabriel-silva](https://github.com/mgabriel-silva))

## [2.0.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.0.1) (2019-04-05)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/2.0.0...2.0.1)

**Fixed bugs:**

- \[Bug\] Invalid version for stable Docker image [\#453](https://github.com/TheHive-Project/Cortex-Analyzers/issues/453)

## [2.0.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/2.0.0) (2019-04-05)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.16.0...2.0.0)

**Closed issues:**

- \[FR\] Remove contrib folder [\#451](https://github.com/TheHive-Project/Cortex-Analyzers/issues/451)
- \[FR\] Add support to dockerized analyzers [\#450](https://github.com/TheHive-Project/Cortex-Analyzers/issues/450)

## [1.16.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.16.0) (2019-03-27)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.15.3...1.16.0)

**Implemented enhancements:**

- AbuseIPDB analyzer creation [\#353](https://github.com/TheHive-Project/Cortex-Analyzers/issues/353)

**Fixed bugs:**

- \[Bug\] [\#433](https://github.com/TheHive-Project/Cortex-Analyzers/issues/433)

**Closed issues:**

- Different analyzer results between manually built instance and trainingVM [\#442](https://github.com/TheHive-Project/Cortex-Analyzers/issues/442)
- Crowdstrike Falcon Responder [\#423](https://github.com/TheHive-Project/Cortex-Analyzers/issues/423)
- Backscatter.io Analyzer [\#422](https://github.com/TheHive-Project/Cortex-Analyzers/issues/422)

**Merged pull requests:**

- Add responder QRadarAutoClose\[FR\#441\] [\#443](https://github.com/TheHive-Project/Cortex-Analyzers/pull/443) ([cyberpescadito](https://github.com/cyberpescadito))
- added templates for AbuseIPDB [\#425](https://github.com/TheHive-Project/Cortex-Analyzers/pull/425) ([mlodic](https://github.com/mlodic))
- A responder for the Crowdstrike Falcon custom IOC api [\#421](https://github.com/TheHive-Project/Cortex-Analyzers/pull/421) ([ag-michael](https://github.com/ag-michael))
- New analyzer: Backscatter.io [\#420](https://github.com/TheHive-Project/Cortex-Analyzers/pull/420) ([9b](https://github.com/9b))
- Added AbuseIPDB analyzer [\#400](https://github.com/TheHive-Project/Cortex-Analyzers/pull/400) ([mlodic](https://github.com/mlodic))

## [1.15.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.15.3) (2019-02-28)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.15.2...1.15.3)

**Implemented enhancements:**

- \[FR\] New URLhaus API [\#431](https://github.com/TheHive-Project/Cortex-Analyzers/issues/431)
- Updating Cuckoo Analyzer/Report Templates [\#418](https://github.com/TheHive-Project/Cortex-Analyzers/pull/418) ([nicpenning](https://github.com/nicpenning))

**Fixed bugs:**

- Proofpoint analyzer fails Unexpected Error: Unicode-objects must be encoded before hashing [\#417](https://github.com/TheHive-Project/Cortex-Analyzers/issues/417)

## [1.15.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.15.2) (2019-02-11)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.15.1...1.15.2)

**Implemented enhancements:**

- Wrong File handling in OTXQuery Analyzer [\#313](https://github.com/TheHive-Project/Cortex-Analyzers/issues/313)

**Fixed bugs:**

- MISP Analyzer only queries first configured MISP instance [\#378](https://github.com/TheHive-Project/Cortex-Analyzers/issues/378)
- Issue with encoding in mailer responder [\#416](https://github.com/TheHive-Project/Cortex-Analyzers/issues/416)
- Restrict UnshortenLink usage to urls without IPs and/or ports [\#413](https://github.com/TheHive-Project/Cortex-Analyzers/issues/413)
- Crtsh Analyzer: crt.sh result is a nested list [\#410](https://github.com/TheHive-Project/Cortex-Analyzers/issues/410)
- MISP: fix requirements; enum not required for python 3.4+ [\#409](https://github.com/TheHive-Project/Cortex-Analyzers/issues/409)
- FileInfo Manalyze - \[plugin\_btcaddress\] Renamed to plugin\_cryptoaddress. [\#408](https://github.com/TheHive-Project/Cortex-Analyzers/issues/408)
-  Bug: a broken link in the Cymon\_Check\_IP report [\#406](https://github.com/TheHive-Project/Cortex-Analyzers/issues/406)
- Fix for \#410 removed wrapping of crt.sh result in a list [\#411](https://github.com/TheHive-Project/Cortex-Analyzers/pull/411) ([sprungknoedl](https://github.com/sprungknoedl))

**Closed issues:**

- EmlParser\_1\_1 not parsing .msg files [\#401](https://github.com/TheHive-Project/Cortex-Analyzers/issues/401)

**Merged pull requests:**

- Fix a broken link in the Cymon\_Check\_IP report [\#407](https://github.com/TheHive-Project/Cortex-Analyzers/pull/407) ([ninoseki](https://github.com/ninoseki))

## [1.15.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.15.1) (2019-01-09)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.15.0...1.15.1)

**Fixed bugs:**

- Wrong command path in HIBP\_Query.json [\#404](https://github.com/TheHive-Project/Cortex-Analyzers/issues/404)
- fix the lack of dependency called enum in ubuntu 16.04 [\#398](https://github.com/TheHive-Project/Cortex-Analyzers/pull/398) ([yojo3000](https://github.com/yojo3000))

**Closed issues:**

- Malwares Analyzer for Python 3.4+ [\#402](https://github.com/TheHive-Project/Cortex-Analyzers/issues/402)

**Merged pull requests:**

- make code python 3.4 compatible [\#403](https://github.com/TheHive-Project/Cortex-Analyzers/pull/403) ([dadokkio](https://github.com/dadokkio))

## [1.15.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.15.0) (2018-12-20)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.14.4...1.15.0)

**Implemented enhancements:**

- Improvement: Eml\_Parser Analyzer & Template [\#394](https://github.com/TheHive-Project/Cortex-Analyzers/issues/394)
- Revamp Shodan analyzer [\#327](https://github.com/TheHive-Project/Cortex-Analyzers/issues/327)
- Update DomainTools analyzer with new flavors [\#320](https://github.com/TheHive-Project/Cortex-Analyzers/issues/320)
- Add support for query parameters in DNSDB [\#318](https://github.com/TheHive-Project/Cortex-Analyzers/issues/318)
- Improvement: Eml\_Parser Analyzer & Template [\#393](https://github.com/TheHive-Project/Cortex-Analyzers/pull/393) ([arnydo](https://github.com/arnydo))
- Analyzer/Umbrella & Templates [\#392](https://github.com/TheHive-Project/Cortex-Analyzers/pull/392) ([arnydo](https://github.com/arnydo))
- Improve/mailer [\#376](https://github.com/TheHive-Project/Cortex-Analyzers/pull/376) ([arnydo](https://github.com/arnydo))
- Additional features for IBM X-force plug-in [\#368](https://github.com/TheHive-Project/Cortex-Analyzers/pull/368) ([jeffrey-e](https://github.com/jeffrey-e))
- Revamp Shodan analyzer [\#328](https://github.com/TheHive-Project/Cortex-Analyzers/pull/328) ([amr-cossi](https://github.com/amr-cossi))
- Feature/domain tools more flavors [\#321](https://github.com/TheHive-Project/Cortex-Analyzers/pull/321) ([amr-cossi](https://github.com/amr-cossi))

**Fixed bugs:**

- Fortigard Report Template needs to be updated with new reclassification url [\#345](https://github.com/TheHive-Project/Cortex-Analyzers/issues/345)

**Closed issues:**

- Analyzer report samples/examples [\#390](https://github.com/TheHive-Project/Cortex-Analyzers/issues/390)
- New Analyzer: Cisco Umbrella Reporting [\#385](https://github.com/TheHive-Project/Cortex-Analyzers/issues/385)
- Cisco Umbrella Blacklister Responder [\#382](https://github.com/TheHive-Project/Cortex-Analyzers/issues/382)
- New analyzer : Cyberprotect ThreatScore [\#373](https://github.com/TheHive-Project/Cortex-Analyzers/issues/373)
- New Analyzer: SecurityTrails [\#370](https://github.com/TheHive-Project/Cortex-Analyzers/issues/370)
- Analyzer - Haveibeenpwned.com Lookup [\#190](https://github.com/TheHive-Project/Cortex-Analyzers/issues/190)

**Merged pull requests:**

- Adding Patrowl analyzer [\#386](https://github.com/TheHive-Project/Cortex-Analyzers/pull/386) ([MaKyOtOx](https://github.com/MaKyOtOx))
- Responder/umbrella blacklister [\#383](https://github.com/TheHive-Project/Cortex-Analyzers/pull/383) ([arnydo](https://github.com/arnydo))
- HIBP\_Query - Option to include Unverified Breaches [\#381](https://github.com/TheHive-Project/Cortex-Analyzers/pull/381) ([arnydo](https://github.com/arnydo))
- New analyzer : Cyberprotect ThreatScore [\#374](https://github.com/TheHive-Project/Cortex-Analyzers/pull/374) ([remiallain](https://github.com/remiallain))
- feat: add SecurityTrails analyzers [\#371](https://github.com/TheHive-Project/Cortex-Analyzers/pull/371) ([ninoseki](https://github.com/ninoseki))
- Added HIBP Analyzer with templates [\#367](https://github.com/TheHive-Project/Cortex-Analyzers/pull/367) ([crackytsi](https://github.com/crackytsi))
- Fix Fortiguard reclassification request URL [\#346](https://github.com/TheHive-Project/Cortex-Analyzers/pull/346) ([megan201296](https://github.com/megan201296))
- Add DNSDB API parameters [\#319](https://github.com/TheHive-Project/Cortex-Analyzers/pull/319) ([amr-cossi](https://github.com/amr-cossi))

## [1.14.4](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.14.4) (2018-12-05)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.14.3...1.14.4)

**Implemented enhancements:**

- Add option to specify SMTP Port for Mailer Responder [\#377](https://github.com/TheHive-Project/Cortex-Analyzers/issues/377)
- Virustotal: update short reports to distinguish Scan from GetReport flavors [\#389](https://github.com/TheHive-Project/Cortex-Analyzers/issues/389)

**Fixed bugs:**

- Virustotal: update short reports to distinguish Scan from GetReport flavors [\#389](https://github.com/TheHive-Project/Cortex-Analyzers/issues/389)
- msg-extractor library has been updated and brakes FileInfo analyzer [\#384](https://github.com/TheHive-Project/Cortex-Analyzers/issues/384)

## [1.14.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.14.3) (2018-11-28)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.14.2...1.14.3)

**Fixed bugs:**

- eml\_parser Unexpected Error: list index out of range [\#352](https://github.com/TheHive-Project/Cortex-Analyzers/issues/352)

**Closed issues:**

- CERTatPassiveDNS\_2\_0 Invalid File for WHOIS.sh [\#349](https://github.com/TheHive-Project/Cortex-Analyzers/issues/349)

## [1.14.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.14.2) (2018-11-16)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.14.1...1.14.2)

**Fixed bugs:**

- Fix URLHaus long template [\#375](https://github.com/TheHive-Project/Cortex-Analyzers/issues/375)

## [1.14.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.14.1) (2018-11-09)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.14.0...1.14.1)

**Implemented enhancements:**

- Fix for Fortiguard to handle FQDNs as well as domains and urls [\#358](https://github.com/TheHive-Project/Cortex-Analyzers/pull/358) ([phpsystems](https://github.com/phpsystems))

**Fixed bugs:**

- Proofpoint analyzer definition missing the configuration objects [\#366](https://github.com/TheHive-Project/Cortex-Analyzers/issues/366)
- fix in case GSB value is missing [\#365](https://github.com/TheHive-Project/Cortex-Analyzers/pull/365) ([garanews](https://github.com/garanews))
- fix: "cut: the delimiter must be a single character" [\#364](https://github.com/TheHive-Project/Cortex-Analyzers/pull/364) ([garanews](https://github.com/garanews))

**Closed issues:**

- FileInfo 5.0 Dockerized .exe analysis [\#369](https://github.com/TheHive-Project/Cortex-Analyzers/issues/369)

## [1.14.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.14.0) (2018-10-26)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.13.2...1.14.0)

**Implemented enhancements:**

- MISP WarningLists CIDR notation support [\#197](https://github.com/TheHive-Project/Cortex-Analyzers/issues/197)
- Fixes file not found issue and empty result set in CERT.at passive dns analyzer [\#362](https://github.com/TheHive-Project/Cortex-Analyzers/issues/362)
- Add RTF support in FileInfo [\#360](https://github.com/TheHive-Project/Cortex-Analyzers/issues/360)
- PassiveTotal\_Passive\_Dns\_2\_0 ordering issue [\#329](https://github.com/TheHive-Project/Cortex-Analyzers/issues/329)
- Add new flavors in Onyphe analyzer [\#324](https://github.com/TheHive-Project/Cortex-Analyzers/issues/324)
- Urlscan Analyzer [\#131](https://github.com/TheHive-Project/Cortex-Analyzers/issues/131)
- PassiveTotal\_Passive\_Dns\_2\_0: Improve the ordering of the records [\#330](https://github.com/TheHive-Project/Cortex-Analyzers/pull/330) ([ninoseki](https://github.com/ninoseki))
- Fix a typo in URLhaus's long.html [\#348](https://github.com/TheHive-Project/Cortex-Analyzers/pull/348) ([ninoseki](https://github.com/ninoseki))
- Add RecordedFuture Analyzer [\#347](https://github.com/TheHive-Project/Cortex-Analyzers/pull/347) ([jojoob](https://github.com/jojoob))
- Add urlscan.io search analyzer [\#337](https://github.com/TheHive-Project/Cortex-Analyzers/pull/337) ([ninoseki](https://github.com/ninoseki))
- Add Datascan and Inetnum flavors [\#326](https://github.com/TheHive-Project/Cortex-Analyzers/pull/326) ([amr-cossi](https://github.com/amr-cossi))
- New Analyzer: Investigate [\#310](https://github.com/TheHive-Project/Cortex-Analyzers/pull/310) ([yasty](https://github.com/yasty))
- New analyzer : Google DNS over HTTPS [\#305](https://github.com/TheHive-Project/Cortex-Analyzers/pull/305) ([0xswitch](https://github.com/0xswitch))

**Fixed bugs:**

- Cortex Responder - Invalid Output [\#331](https://github.com/TheHive-Project/Cortex-Analyzers/issues/331)
- Fixes file not found issue and empty result set in CERT.at passive dns analyzer [\#362](https://github.com/TheHive-Project/Cortex-Analyzers/issues/362)
- Force python3 for MISP-Analyzer [\#356](https://github.com/TheHive-Project/Cortex-Analyzers/issues/356)
- HybridAnalysis analyzer does not properly handle filenames on some cases [\#323](https://github.com/TheHive-Project/Cortex-Analyzers/issues/323)

**Closed issues:**

- Joe Sandbox Analyzer returning error with Joe Sandbox Cloud Pro [\#357](https://github.com/TheHive-Project/Cortex-Analyzers/issues/357)
- Yara analyzer: 'can't open include file' [\#354](https://github.com/TheHive-Project/Cortex-Analyzers/issues/354)
- Add support to responders in cortexutils [\#316](https://github.com/TheHive-Project/Cortex-Analyzers/issues/316)
- Could not get Yeti analyzer worked in cortex [\#307](https://github.com/TheHive-Project/Cortex-Analyzers/issues/307)
- Request for a Cortex Analyzer for Recorded Future [\#102](https://github.com/TheHive-Project/Cortex-Analyzers/issues/102)
- New Analyzer: Investigate [\#309](https://github.com/TheHive-Project/Cortex-Analyzers/issues/309)
- New analyzer : Google DNS over HTTPS  [\#306](https://github.com/TheHive-Project/Cortex-Analyzers/issues/306)
- Proofpoint Forensics Lookup [\#117](https://github.com/TheHive-Project/Cortex-Analyzers/issues/117)

## [1.13.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.13.2) (2018-10-16)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.13.1...1.13.2)

**Fixed bugs:**

- Cuckoo file submission Analyzer error [\#177](https://github.com/TheHive-Project/Cortex-Analyzers/issues/177)

## [1.13.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.13.1) (2018-09-19)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.13.0...1.13.1)

**Fixed bugs:**

- Wrong datatype in artifact\(\) in DShield analyzer  [\#344](https://github.com/TheHive-Project/Cortex-Analyzers/issues/344)

## [1.13.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.13.0) (2018-09-18)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.12.0...1.13.0)

**Implemented enhancements:**

- Whois History  has no mini report [\#339](https://github.com/TheHive-Project/Cortex-Analyzers/issues/339)
- New analyzer: Pulsedive [\#303](https://github.com/TheHive-Project/Cortex-Analyzers/issues/303)
- New analyzer : Hunter.io [\#293](https://github.com/TheHive-Project/Cortex-Analyzers/issues/293)
- add Phishing Initiative Scan analyzer. [\#317](https://github.com/TheHive-Project/Cortex-Analyzers/pull/317) ([sigalpes](https://github.com/sigalpes))
- New analyzer: DShield [\#300](https://github.com/TheHive-Project/Cortex-Analyzers/pull/300) ([xme](https://github.com/xme))
- Fortiguard url taxonomy [\#296](https://github.com/TheHive-Project/Cortex-Analyzers/pull/296) ([srilumpa](https://github.com/srilumpa))
- New analyzer: Hunter.io [\#294](https://github.com/TheHive-Project/Cortex-Analyzers/pull/294) ([remiallain](https://github.com/remiallain))

**Fixed bugs:**

- Fix issues with VMRay analyzer [\#332](https://github.com/TheHive-Project/Cortex-Analyzers/issues/332)
- Fix code in Domaintools analyzer [\#341](https://github.com/TheHive-Project/Cortex-Analyzers/issues/341)
- Wrong template in C1fApp analyzer short report [\#340](https://github.com/TheHive-Project/Cortex-Analyzers/issues/340)
- MISP Analysis failes  [\#335](https://github.com/TheHive-Project/Cortex-Analyzers/issues/335)
- \[URLhaus\] Change of format from URLhaus [\#308](https://github.com/TheHive-Project/Cortex-Analyzers/issues/308)
- FortiGuard URL: taxonomy is too rigid [\#295](https://github.com/TheHive-Project/Cortex-Analyzers/issues/295)

**Closed issues:**

- Cortex Responder - "thehive:log" datatype [\#343](https://github.com/TheHive-Project/Cortex-Analyzers/issues/343)
- DomainTools Analyzer Risk is broken. Gives authentication errors [\#338](https://github.com/TheHive-Project/Cortex-Analyzers/issues/338)
- StopForumSpam analyzer [\#205](https://github.com/TheHive-Project/Cortex-Analyzers/issues/205)
- Fireeye iSIGHT Analyzer [\#160](https://github.com/TheHive-Project/Cortex-Analyzers/issues/160)
- Manalyze analyzer [\#116](https://github.com/TheHive-Project/Cortex-Analyzers/issues/116)

**Merged pull requests:**

- Manalyze submodule for FileInfo analyzer [\#333](https://github.com/TheHive-Project/Cortex-Analyzers/pull/333) ([3c7](https://github.com/3c7))

## [1.12.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.12.0) (2018-07-31)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.11.0...1.12.0)

**Merged pull requests:**

- Eml Parser analyzer [\#260](https://github.com/TheHive-Project/Cortex-Analyzers/pull/260) ([ninSmith](https://github.com/ninSmith))

## [1.11.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.11.0) (2018-07-13)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.10.4...1.11.0)

**Implemented enhancements:**

- New DomainTools API services requires new analyzer [\#240](https://github.com/TheHive-Project/Cortex-Analyzers/issues/240)
- remove double quotes in short reports [\#291](https://github.com/TheHive-Project/Cortex-Analyzers/issues/291)
- Update DomainTools Analyzer to pull Risk and Proximity Score [\#214](https://github.com/TheHive-Project/Cortex-Analyzers/issues/214)
- \[OS3 Hackathon\] Refactor File\_Info Analyzer [\#212](https://github.com/TheHive-Project/Cortex-Analyzers/issues/212)
- VirusTotal URL report [\#289](https://github.com/TheHive-Project/Cortex-Analyzers/pull/289) ([srilumpa](https://github.com/srilumpa))
- Add URLHaus analyzer [\#271](https://github.com/TheHive-Project/Cortex-Analyzers/pull/271) ([3c7](https://github.com/3c7))

**Fixed bugs:**

- Analyzer Issue : Abuse\_Finder  [\#277](https://github.com/TheHive-Project/Cortex-Analyzers/issues/277)
- Malwares analyzer has wrong api URL  [\#292](https://github.com/TheHive-Project/Cortex-Analyzers/issues/292)
- MISP analyzer certificate validation and name configuration [\#286](https://github.com/TheHive-Project/Cortex-Analyzers/issues/286)
- FileInfo fixes [\#281](https://github.com/TheHive-Project/Cortex-Analyzers/issues/281)

**Closed issues:**

- disable [\#301](https://github.com/TheHive-Project/Cortex-Analyzers/issues/301)
- New analyzer: DShield [\#299](https://github.com/TheHive-Project/Cortex-Analyzers/issues/299)
- New Analyzer: hashdd [\#282](https://github.com/TheHive-Project/Cortex-Analyzers/issues/282)

**Merged pull requests:**

- Feature/urlhaus analyzer [\#285](https://github.com/TheHive-Project/Cortex-Analyzers/pull/285) ([ninoseki](https://github.com/ninoseki))
- Add hashdd analyzer [\#284](https://github.com/TheHive-Project/Cortex-Analyzers/pull/284) ([iosonogio](https://github.com/iosonogio))

## [1.10.4](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.10.4) (2018-06-23)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.10.3...1.10.4)

**Fixed bugs:**

- IBM X-Force and Abuse finder problems found in shorts and long report [\#290](https://github.com/TheHive-Project/Cortex-Analyzers/issues/290)

## [1.10.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.10.3) (2018-06-18)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.10.2...1.10.3)

**Implemented enhancements:**

- New analyzer : Threatcrowd [\#243](https://github.com/TheHive-Project/Cortex-Analyzers/issues/243)
- Msg\_Parser analyser show for all files [\#136](https://github.com/TheHive-Project/Cortex-Analyzers/issues/136)

**Fixed bugs:**

- ibm xforce analyzer "show-all" buttons don't work [\#287](https://github.com/TheHive-Project/Cortex-Analyzers/issues/287)

**Closed issues:**

- Ofuscating an IOC signature before analyzing on VT  [\#288](https://github.com/TheHive-Project/Cortex-Analyzers/issues/288)
- IBM X-Force Exchange Analyzer [\#144](https://github.com/TheHive-Project/Cortex-Analyzers/issues/144)
- API Keys to be submitted through Cortex for Analyzers [\#7](https://github.com/TheHive-Project/Cortex-Analyzers/issues/7)

## [1.10.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.10.2) (2018-06-08)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.10.1...1.10.2)

**Fixed bugs:**

- File encoding issue in Threatcrowd json file [\#283](https://github.com/TheHive-Project/Cortex-Analyzers/issues/283)
- IBMXForce template name [\#280](https://github.com/TheHive-Project/Cortex-Analyzers/issues/280)
- Allow to set self signed certificates in VMRay analyzer [\#279](https://github.com/TheHive-Project/Cortex-Analyzers/issues/279)
- IBMXforce Analyzer forces TLP1 [\#278](https://github.com/TheHive-Project/Cortex-Analyzers/issues/278)
- Greynoise minireport does not give any info when there is no record in report [\#275](https://github.com/TheHive-Project/Cortex-Analyzers/issues/275)
- encoding problem in ThreatCrowd [\#273](https://github.com/TheHive-Project/Cortex-Analyzers/issues/273)

**Closed issues:**

- Yara config for multi pathes is not parsing correctly in platform [\#274](https://github.com/TheHive-Project/Cortex-Analyzers/issues/274)

## [1.10.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.10.1) (2018-06-06)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.10.0...1.10.1)

**Fixed bugs:**

- Wrong name for Staxx report template [\#272](https://github.com/TheHive-Project/Cortex-Analyzers/issues/272)

## [1.10.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.10.0) (2018-06-06)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.7...1.10.0)

**Implemented enhancements:**

- New analyzer: malwares.com [\#251](https://github.com/TheHive-Project/Cortex-Analyzers/issues/251)
- Release 1.10.0 [\#270](https://github.com/TheHive-Project/Cortex-Analyzers/issues/270)
- No short report in Hybrid-Analysis when there is no result [\#267](https://github.com/TheHive-Project/Cortex-Analyzers/issues/267)
- Add ip dataType to CERT.at Passive DNS analyzer [\#237](https://github.com/TheHive-Project/Cortex-Analyzers/issues/237)
- Grey Noise analyzer [\#231](https://github.com/TheHive-Project/Cortex-Analyzers/issues/231)
- URLhaus analyzer [\#226](https://github.com/TheHive-Project/Cortex-Analyzers/issues/226)
- cybercrime-tracker.net analyzer [\#220](https://github.com/TheHive-Project/Cortex-Analyzers/issues/220)
- Anomali Staxx Analyzer [\#180](https://github.com/TheHive-Project/Cortex-Analyzers/issues/180)
- Develop branch, add Staxx Analyzer [\#263](https://github.com/TheHive-Project/Cortex-Analyzers/pull/263) ([robertnixon2003](https://github.com/robertnixon2003))
- Improve EmergingThreats analyzers [\#259](https://github.com/TheHive-Project/Cortex-Analyzers/pull/259) ([ant1](https://github.com/ant1))
- Created Mnemonic PDNS public and closed analyzers [\#256](https://github.com/TheHive-Project/Cortex-Analyzers/pull/256) ([NFCERT](https://github.com/NFCERT))
- New analyzer: malwares.com [\#252](https://github.com/TheHive-Project/Cortex-Analyzers/pull/252) ([garanews](https://github.com/garanews))
- add UnshortenLink analyzer [\#247](https://github.com/TheHive-Project/Cortex-Analyzers/pull/247) ([sigalpes](https://github.com/sigalpes))
- add threatcrowd analyzer [\#244](https://github.com/TheHive-Project/Cortex-Analyzers/pull/244) ([remiallain](https://github.com/remiallain))
- JoeSandbox analyzers: use a sane analysis timeout [\#239](https://github.com/TheHive-Project/Cortex-Analyzers/pull/239) ([ant1](https://github.com/ant1))
- GreyNoise analyzer [\#236](https://github.com/TheHive-Project/Cortex-Analyzers/pull/236) ([danielbrowne](https://github.com/danielbrowne))
- cybercrime-tracker.net analyzer [\#222](https://github.com/TheHive-Project/Cortex-Analyzers/pull/222) ([ph34tur3](https://github.com/ph34tur3))
- created IBMXForce analyzer [\#187](https://github.com/TheHive-Project/Cortex-Analyzers/pull/187) ([garanews](https://github.com/garanews))

**Fixed bugs:**

- Release 1.10.0 [\#270](https://github.com/TheHive-Project/Cortex-Analyzers/issues/270)
- No short report in Hybrid-Analysis when there is no result [\#267](https://github.com/TheHive-Project/Cortex-Analyzers/issues/267)
- Payloadsecurity [\#262](https://github.com/TheHive-Project/Cortex-Analyzers/issues/262)
- Bug in EmergingThreats\_MalwareInfo analyzer [\#258](https://github.com/TheHive-Project/Cortex-Analyzers/issues/258)
- Error in permalink in Cymon long report template [\#238](https://github.com/TheHive-Project/Cortex-Analyzers/issues/238)
- Added the executable flag to cuckoosandbox\_analyzer.py [\#266](https://github.com/TheHive-Project/Cortex-Analyzers/pull/266) ([Jack28](https://github.com/Jack28))
- JoeSandbox analyzers: use a sane analysis timeout [\#239](https://github.com/TheHive-Project/Cortex-Analyzers/pull/239) ([ant1](https://github.com/ant1))
- MISP WarningLists - Handling IP address lookup in CIDR IP ranges [\#200](https://github.com/TheHive-Project/Cortex-Analyzers/pull/200) ([srilumpa](https://github.com/srilumpa))

**Closed issues:**

- Create GreyNoise analyzer template [\#269](https://github.com/TheHive-Project/Cortex-Analyzers/issues/269)

## [1.9.7](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.7) (2018-05-29)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.6...1.9.7)

**Implemented enhancements:**

- Update analyzers configuration for Cortex2 [\#172](https://github.com/TheHive-Project/Cortex-Analyzers/issues/172)
- Download only new hash files [\#242](https://github.com/TheHive-Project/Cortex-Analyzers/pull/242) ([ktneely](https://github.com/ktneely))

**Fixed bugs:**

- Yara no longer processing rules after cortex 2.0 update [\#245](https://github.com/TheHive-Project/Cortex-Analyzers/issues/245)

**Closed issues:**

- extend templates with external libraries [\#250](https://github.com/TheHive-Project/Cortex-Analyzers/issues/250)
- Bluecoat Analyzer [\#85](https://github.com/TheHive-Project/Cortex-Analyzers/issues/85)

## [1.9.6](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.6) (2018-04-25)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.5...1.9.6)

**Fixed bugs:**

- Yeti pyton lib fails to install for python\_version \> 2.7 [\#241](https://github.com/TheHive-Project/Cortex-Analyzers/issues/241)

## [1.9.5](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.5) (2018-04-18)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.4...1.9.5)

**Fixed bugs:**

- Remove emerging threat wrong template files [\#233](https://github.com/TheHive-Project/Cortex-Analyzers/issues/233)
- Censys analyzer : no uid given but the parameter is set [\#232](https://github.com/TheHive-Project/Cortex-Analyzers/issues/232)

## [1.9.4](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.4) (2018-04-13)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.3...1.9.4)

**Implemented enhancements:**

- CIRCLPassiveSSL\_2\_0 requires colons or dashes in hashes [\#229](https://github.com/TheHive-Project/Cortex-Analyzers/issues/229)

**Fixed bugs:**

- Hybrid Analysis returns success when filename query didn't work [\#223](https://github.com/TheHive-Project/Cortex-Analyzers/issues/223)
- Fix JSB Url Analysis template [\#207](https://github.com/TheHive-Project/Cortex-Analyzers/pull/207) ([ant1](https://github.com/ant1))

**Merged pull requests:**

- Add URLhaus analyzer [\#227](https://github.com/TheHive-Project/Cortex-Analyzers/pull/227) ([ninoseki](https://github.com/ninoseki))

## [1.9.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.3) (2018-04-09)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.2...1.9.3)

**Implemented enhancements:**

- Cuckoo Analyzer changes the name of the file [\#188](https://github.com/TheHive-Project/Cortex-Analyzers/issues/188)

**Fixed bugs:**

- Fix the default config of Cymon\_Check\_IP analyzer [\#225](https://github.com/TheHive-Project/Cortex-Analyzers/issues/225)
- Restrict abuse\_finder and file\_info dependencies to Python 2.7 [\#224](https://github.com/TheHive-Project/Cortex-Analyzers/issues/224)
- MISPWarningLists Analyzer searches for hashes case sensitive [\#221](https://github.com/TheHive-Project/Cortex-Analyzers/issues/221)
- Bluecoat Categorization failes [\#216](https://github.com/TheHive-Project/Cortex-Analyzers/issues/216)
- View All in template long not working [\#208](https://github.com/TheHive-Project/Cortex-Analyzers/issues/208)

**Closed issues:**

- Feature Request: haveibeenpwned.com [\#189](https://github.com/TheHive-Project/Cortex-Analyzers/issues/189)

## [1.9.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.2) (2018-04-04)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.1...1.9.2)

**Fixed bugs:**

- Hybrid Analysis analyzer successful even if rate limit reached [\#215](https://github.com/TheHive-Project/Cortex-Analyzers/issues/215)
- Data field missing on file submission [\#218](https://github.com/TheHive-Project/Cortex-Analyzers/issues/218)

**Closed issues:**

- Supper the new auto extract config name [\#219](https://github.com/TheHive-Project/Cortex-Analyzers/issues/219)
- OTXQuery\_2\_0 failes with Cortex2 [\#217](https://github.com/TheHive-Project/Cortex-Analyzers/issues/217)

## [1.9.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.1) (2018-03-30)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.9.0...1.9.1)

## [1.9.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.9.0) (2018-03-29)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.8.3...1.9.0)

**Implemented enhancements:**

- DomainTools\_ReverseIP should accept fqdn and/or domain as datatype [\#193](https://github.com/TheHive-Project/Cortex-Analyzers/issues/193)
- Manage domain datatype in Name\_history service of DNSDB analyzer [\#183](https://github.com/TheHive-Project/Cortex-Analyzers/issues/183)
- Manage fqdn datatype in domain\_name service of DNSDB analyzer [\#182](https://github.com/TheHive-Project/Cortex-Analyzers/issues/182)
- Improve Phishtank maliciousness results  [\#181](https://github.com/TheHive-Project/Cortex-Analyzers/issues/181)
- IP type for CIRCL Passive DNS and others [\#99](https://github.com/TheHive-Project/Cortex-Analyzers/issues/99)
- added Malpedia Analyzer [\#168](https://github.com/TheHive-Project/Cortex-Analyzers/pull/168) ([garanews](https://github.com/garanews))

**Fixed bugs:**

- Fortiguard analyzer : use HTTPS to request fortiguard service [\#201](https://github.com/TheHive-Project/Cortex-Analyzers/issues/201)
- DomainTools\\_ReverseIP should accept fqdn and/or domain as datatype [\#193](https://github.com/TheHive-Project/Cortex-Analyzers/issues/193)

**Merged pull requests:**

- Addedd cymon cortex analyzers [\#133](https://github.com/TheHive-Project/Cortex-Analyzers/pull/133) ([ST2Labs](https://github.com/ST2Labs))

## [1.8.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.8.3) (2018-03-23)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.8.2...1.8.3)

**Fixed bugs:**

- Abuse\_Finder\_2\_0 - Invalid analyzer output format [\#211](https://github.com/TheHive-Project/Cortex-Analyzers/issues/211)
- Bug in Abuse\_Finder Analyzer [\#161](https://github.com/TheHive-Project/Cortex-Analyzers/issues/161)

## [1.8.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.8.2) (2018-03-21)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.8.1...1.8.2)

**Fixed bugs:**

- Cortex-Analyzer - MISP-plugin without proxy support/recognition [\#209](https://github.com/TheHive-Project/Cortex-Analyzers/issues/209)
- Bug: FortiGuard URLCategory Failure [\#203](https://github.com/TheHive-Project/Cortex-Analyzers/issues/203)
- Onyphe\_Ports\_1\_0 return bad data in JSON object [\#169](https://github.com/TheHive-Project/Cortex-Analyzers/issues/169)
- Joe Sandbox Analyzer returning error [\#156](https://github.com/TheHive-Project/Cortex-Analyzers/issues/156)
- use https for request [\#204](https://github.com/TheHive-Project/Cortex-Analyzers/pull/204) ([ecapuano](https://github.com/ecapuano))
- MISP WarningLists reports [\#196](https://github.com/TheHive-Project/Cortex-Analyzers/pull/196) ([srilumpa](https://github.com/srilumpa))

**Closed issues:**

- Cortex-Analyzer - MISP-plugin no "ssl-verify = False" option [\#210](https://github.com/TheHive-Project/Cortex-Analyzers/issues/210)
- MISP WarningLists long report does not display results [\#195](https://github.com/TheHive-Project/Cortex-Analyzers/issues/195)
- error in MISP/requirements.txt [\#179](https://github.com/TheHive-Project/Cortex-Analyzers/issues/179)

**Merged pull requests:**

- Fixes some problems with automatic artifact extraction [\#184](https://github.com/TheHive-Project/Cortex-Analyzers/pull/184) ([3c7](https://github.com/3c7))

## [1.8.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.8.1) (2018-02-05)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.8.0...1.8.1)

**Implemented enhancements:**

- Updating VMRay Analyzer to accept files as dataType [\#157](https://github.com/TheHive-Project/Cortex-Analyzers/issues/157)

**Fixed bugs:**

- Bluecoat analyzer fails if domain contains subdomain [\#173](https://github.com/TheHive-Project/Cortex-Analyzers/issues/173)

**Closed issues:**

- Malpedia \(yara\) Analyzer [\#166](https://github.com/TheHive-Project/Cortex-Analyzers/issues/166)

## [1.8.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.8.0) (2018-01-11)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.7.1...1.8.0)

**Implemented enhancements:**

- VirusTotal ignores Environment Proxies [\#130](https://github.com/TheHive-Project/Cortex-Analyzers/issues/130)
- WIP: PEP8 all the things [\#165](https://github.com/TheHive-Project/Cortex-Analyzers/pull/165) ([3c7](https://github.com/3c7))
- Feature/bluecoat [\#84](https://github.com/TheHive-Project/Cortex-Analyzers/pull/84) ([0xswitch](https://github.com/0xswitch))
- Fixes \#149, removes download\_hashes.py [\#155](https://github.com/TheHive-Project/Cortex-Analyzers/pull/155) ([3c7](https://github.com/3c7))
- Joe Sandbox API version 2 support [\#141](https://github.com/TheHive-Project/Cortex-Analyzers/pull/141) ([ant1](https://github.com/ant1))

**Fixed bugs:**

- MISP analyzer certpath option doesn't accept bool value [\#164](https://github.com/TheHive-Project/Cortex-Analyzers/issues/164)
- VirusShare downloader bash script bug [\#149](https://github.com/TheHive-Project/Cortex-Analyzers/issues/149)
- Cuckoo Analysis Fails [\#162](https://github.com/TheHive-Project/Cortex-Analyzers/issues/162)
- Fix getting filenames in analyzers [\#140](https://github.com/TheHive-Project/Cortex-Analyzers/pull/140) ([ant1](https://github.com/ant1))
- fix snort alerts [\#163](https://github.com/TheHive-Project/Cortex-Analyzers/pull/163) ([garanews](https://github.com/garanews))

**Closed issues:**

- Censys.io analyzer [\#135](https://github.com/TheHive-Project/Cortex-Analyzers/issues/135)
- C1fApp Analyzer [\#64](https://github.com/TheHive-Project/Cortex-Analyzers/issues/64)
- URLQuery Analyzer [\#18](https://github.com/TheHive-Project/Cortex-Analyzers/issues/18)
- MISP Warninglists analyzer [\#124](https://github.com/TheHive-Project/Cortex-Analyzers/issues/124)
- PayloadSecurity Sandbox [\#121](https://github.com/TheHive-Project/Cortex-Analyzers/issues/121)
- SinkDB Analyzer [\#112](https://github.com/TheHive-Project/Cortex-Analyzers/issues/112)
- C1fApp OSINT analyzer [\#103](https://github.com/TheHive-Project/Cortex-Analyzers/issues/103)
- TOR Exit Nodes IPs Analyzer [\#45](https://github.com/TheHive-Project/Cortex-Analyzers/issues/45)

**Merged pull requests:**

- Fixed requirements parsing MsgParser/requirements.txt [\#159](https://github.com/TheHive-Project/Cortex-Analyzers/pull/159) ([peasead](https://github.com/peasead))
- Censys.io analyzer [\#153](https://github.com/TheHive-Project/Cortex-Analyzers/pull/153) ([3c7](https://github.com/3c7))
- Fix mode when creating FireHOL ipset directory [\#158](https://github.com/TheHive-Project/Cortex-Analyzers/pull/158) ([srilumpa](https://github.com/srilumpa))
- Add Onyphe analyzers [\#152](https://github.com/TheHive-Project/Cortex-Analyzers/pull/152) ([Pierre-Baudry](https://github.com/Pierre-Baudry))
- Tor blutmagie [\#139](https://github.com/TheHive-Project/Cortex-Analyzers/pull/139) ([srilumpa](https://github.com/srilumpa))
- Tor project analyzer [\#138](https://github.com/TheHive-Project/Cortex-Analyzers/pull/138) ([srilumpa](https://github.com/srilumpa))
- Added SinkDB analyzer [\#134](https://github.com/TheHive-Project/Cortex-Analyzers/pull/134) ([3c7](https://github.com/3c7))
- Added MISP warning lists analyzer [\#129](https://github.com/TheHive-Project/Cortex-Analyzers/pull/129) ([3c7](https://github.com/3c7))
- Robtex API Analyzer [\#105](https://github.com/TheHive-Project/Cortex-Analyzers/pull/105) ([3c7](https://github.com/3c7))

## [1.7.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.7.1) (2017-12-06)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.7.0...1.7.1)

**Closed issues:**

- Issue with Shodan Analyzer [\#150](https://github.com/TheHive-Project/Cortex-Analyzers/issues/150)
- Analyzers using online query fails to use system proxy settings [\#143](https://github.com/TheHive-Project/Cortex-Analyzers/issues/143)
- Hippocampe Analyzer Fails [\#137](https://github.com/TheHive-Project/Cortex-Analyzers/issues/137)

**Merged pull requests:**

- Rename hybridanalysis\_analyzer.py to HybridAnalysis\_analyzer.py [\#151](https://github.com/TheHive-Project/Cortex-Analyzers/pull/151) ([treed593](https://github.com/treed593))

## [1.7.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.7.0) (2017-11-08)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.6.5...1.7.0)

**Implemented enhancements:**

- Cuckoo Analyzer requires final slash [\#113](https://github.com/TheHive-Project/Cortex-Analyzers/issues/113)
- support both cuckoo versions [\#100](https://github.com/TheHive-Project/Cortex-Analyzers/pull/100) ([garanews](https://github.com/garanews))

**Fixed bugs:**

- PhishTank analyzer doesn't work [\#126](https://github.com/TheHive-Project/Cortex-Analyzers/issues/126)
- Missing olefile in MsgParser requirements [\#101](https://github.com/TheHive-Project/Cortex-Analyzers/issues/101)
- VirusTotal URL Scan Bug [\#93](https://github.com/TheHive-Project/Cortex-Analyzers/issues/93)

**Merged pull requests:**

- Fix PhishTank analyzer [\#128](https://github.com/TheHive-Project/Cortex-Analyzers/pull/128) ([ilyaglow](https://github.com/ilyaglow))
- Fixed: hide empty panel from template [\#108](https://github.com/TheHive-Project/Cortex-Analyzers/pull/108) ([dadokkio](https://github.com/dadokkio))
- Fixes MISP Analyzer name bug [\#95](https://github.com/TheHive-Project/Cortex-Analyzers/pull/95) ([3c7](https://github.com/3c7))
- Added VxStream Sandbox \(Hybrid Analysis\) Analyzer [\#73](https://github.com/TheHive-Project/Cortex-Analyzers/pull/73) ([yugoslavskiy](https://github.com/yugoslavskiy))

## [1.6.5](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.6.5) (2017-11-05)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.6.4...1.6.5)

## [1.6.4](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.6.4) (2017-11-04)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.6.3...1.6.4)

**Fixed bugs:**

- name parameter for the MISP analyzer does behave as expected [\#94](https://github.com/TheHive-Project/Cortex-Analyzers/issues/94)
- fixed line break in WOT requirements.txt [\#132](https://github.com/TheHive-Project/Cortex-Analyzers/pull/132) ([peasead](https://github.com/peasead))

**Closed issues:**

- Virusshare short report enhancements if SHA1 hash passed [\#115](https://github.com/TheHive-Project/Cortex-Analyzers/issues/115)
- MISP\_2\_0 analyzer does not seems compatible with python 2.7 [\#90](https://github.com/TheHive-Project/Cortex-Analyzers/issues/90)
- ET Intelligence Analyzer [\#79](https://github.com/TheHive-Project/Cortex-Analyzers/issues/79)
- Use naming conventions for analyzer config properties [\#33](https://github.com/TheHive-Project/Cortex-Analyzers/issues/33)
- Hybrid Analysis Analyzer [\#26](https://github.com/TheHive-Project/Cortex-Analyzers/issues/26)

**Merged pull requests:**

- add Analyzers Shodan [\#125](https://github.com/TheHive-Project/Cortex-Analyzers/pull/125) ([sebdraven](https://github.com/sebdraven))
- ProofPoint Threat Insight Forensics Analyzer [\#123](https://github.com/TheHive-Project/Cortex-Analyzers/pull/123) ([typonino](https://github.com/typonino))
- C1fApp Initial version [\#119](https://github.com/TheHive-Project/Cortex-Analyzers/pull/119) ([etz69](https://github.com/etz69))
- Updated VT Links in Long Report [\#111](https://github.com/TheHive-Project/Cortex-Analyzers/pull/111) ([saadkadhi](https://github.com/saadkadhi))
- Revert "Updated VT links in Long report" [\#110](https://github.com/TheHive-Project/Cortex-Analyzers/pull/110) ([saadkadhi](https://github.com/saadkadhi))
- Updated VT links in Long report [\#98](https://github.com/TheHive-Project/Cortex-Analyzers/pull/98) ([mthlvt](https://github.com/mthlvt))

## [1.6.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.6.3) (2017-09-10)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.6.2...1.6.3)

**Merged pull requests:**

- MISP Analyzer: forgot to add same procedure if using just one MISP-Server [\#91](https://github.com/TheHive-Project/Cortex-Analyzers/pull/91) ([3c7](https://github.com/3c7))

## [1.6.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.6.2) (2017-09-04)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.6.1...1.6.2)

**Closed issues:**

- Invalid Yeti templates folder name [\#89](https://github.com/TheHive-Project/Cortex-Analyzers/issues/89)

**Merged pull requests:**

- Updates to Virusshare analyzer [\#80](https://github.com/TheHive-Project/Cortex-Analyzers/pull/80) ([colinvanniekerk](https://github.com/colinvanniekerk))

## [1.6.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.6.1) (2017-09-04)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.6.0...1.6.1)

**Closed issues:**

- MISPClient.\_\_init\_\_, ssl parameter default to True but later used as filename [\#87](https://github.com/TheHive-Project/Cortex-Analyzers/issues/87)

**Merged pull requests:**

- Fixes bug in MISP client [\#88](https://github.com/TheHive-Project/Cortex-Analyzers/pull/88) ([3c7](https://github.com/3c7))
- Adding netaddr to requirements for nessus analyzer [\#83](https://github.com/TheHive-Project/Cortex-Analyzers/pull/83) ([drewstinnett](https://github.com/drewstinnett))

## [1.6.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.6.0) (2017-07-27)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.5.1...1.6.0)

**Closed issues:**

- WOT analyzer [\#82](https://github.com/TheHive-Project/Cortex-Analyzers/issues/82)
- Add Analyzer for Yeti Platform [\#68](https://github.com/TheHive-Project/Cortex-Analyzers/issues/68)
- Cuckoo Sandbox Analyzer [\#23](https://github.com/TheHive-Project/Cortex-Analyzers/issues/23)

**Merged pull requests:**

- Feature/fireeye\_ax [\#78](https://github.com/TheHive-Project/Cortex-Analyzers/pull/78) ([BrevilleBro](https://github.com/BrevilleBro))
- added WOT analyzer & fixed cuckoo templates issue [\#77](https://github.com/TheHive-Project/Cortex-Analyzers/pull/77) ([garanews](https://github.com/garanews))

## [1.5.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.5.1) (2017-07-13)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.5.0...1.5.1)

**Fixed bugs:**

- Yara analyzer doesn't recognize 'sha1' field name from Yara-rules [\#62](https://github.com/TheHive-Project/Cortex-Analyzers/issues/62)

**Closed issues:**

- Virustotal Scan returning incorrect taxonomy on URL scan [\#74](https://github.com/TheHive-Project/Cortex-Analyzers/issues/74)

**Merged pull requests:**

- Cuckoo Sandbox Analyzer [\#50](https://github.com/TheHive-Project/Cortex-Analyzers/pull/50) ([garanews](https://github.com/garanews))

## [1.5.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.5.0) (2017-07-05)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.4.4...1.5.0)

**Implemented enhancements:**

- Build a taxonomy in cortexutils  [\#66](https://github.com/TheHive-Project/Cortex-Analyzers/issues/66)
- Joe Sandbox 19: New Information in Reports [\#65](https://github.com/TheHive-Project/Cortex-Analyzers/issues/65)
- Review summary\(\) and short reports for https://github.com/CERT-BDF/TheHive/issues/131 [\#56](https://github.com/TheHive-Project/Cortex-Analyzers/issues/56)

**Fixed bugs:**

- Add missing check\_tlp config to GoogleSafeBrowsing analyzer [\#71](https://github.com/TheHive-Project/Cortex-Analyzers/issues/71)
- Fix the URL configuration of Hippocampe analyzer [\#69](https://github.com/TheHive-Project/Cortex-Analyzers/issues/69)
- Abuse\_Finder analyzer analyzes "email" instead of "mail" [\#52](https://github.com/TheHive-Project/Cortex-Analyzers/issues/52)

**Closed issues:**

- Missing newlines in requirements.txt [\#60](https://github.com/TheHive-Project/Cortex-Analyzers/issues/60)
- CERT.at PassiveDNS Analyzer [\#13](https://github.com/TheHive-Project/Cortex-Analyzers/issues/13)

**Merged pull requests:**

- Fixed mistake in blocklist script, added error on missing config [\#67](https://github.com/TheHive-Project/Cortex-Analyzers/pull/67) ([3c7](https://github.com/3c7))
- There were no carriage returns so it would break if you wanted to mass install the analyzer requirements [\#61](https://github.com/TheHive-Project/Cortex-Analyzers/pull/61) ([Popsiclestick](https://github.com/Popsiclestick))

## [1.4.4](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.4.4) (2017-06-15)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.4.3...1.4.4)

**Fixed bugs:**

- Inconsistance between long and short reports in MISP analyzer [\#59](https://github.com/TheHive-Project/Cortex-Analyzers/issues/59)

## [1.4.3](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.4.3) (2017-06-15)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.4.2...1.4.3)

**Fixed bugs:**

- cortexutils fails to generate error reports when the analyzer has no config [\#57](https://github.com/TheHive-Project/Cortex-Analyzers/issues/57)
- Encoding problem in cortexutils [\#54](https://github.com/TheHive-Project/Cortex-Analyzers/issues/54)

## [1.4.2](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.4.2) (2017-05-24)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.4.1...1.4.2)

## [1.4.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.4.1) (2017-05-23)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.4.0...1.4.1)

## [1.4.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.4.0) (2017-05-22)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.3.1...1.4.0)

**Fixed bugs:**

- Fortiguard API Changed [\#37](https://github.com/TheHive-Project/Cortex-Analyzers/issues/37)

**Closed issues:**

- FireHOL blocklists analyzer [\#31](https://github.com/TheHive-Project/Cortex-Analyzers/issues/31)
- VMRay Analyzer [\#16](https://github.com/TheHive-Project/Cortex-Analyzers/issues/16)

**Merged pull requests:**

- corrected for change to fortiguard portal [\#51](https://github.com/TheHive-Project/Cortex-Analyzers/pull/51) ([ecapuano](https://github.com/ecapuano))

## [1.3.1](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.3.1) (2017-05-12)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.3.0...1.3.1)

## [1.3.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.3.0) (2017-05-08)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.2.0...1.3.0)

**Implemented enhancements:**

- Update the polling interval in VT scan analyzer [\#42](https://github.com/TheHive-Project/Cortex-Analyzers/issues/42)
- Add author and url attributes to analyzer descriptior files [\#32](https://github.com/TheHive-Project/Cortex-Analyzers/issues/32)
- Cut python 2 dependency by replacing ioc-parser in cortexutils.analyzer [\#4](https://github.com/TheHive-Project/Cortex-Analyzers/issues/4)
- Added rate limit message for VirusTotal analyzer [\#39](https://github.com/TheHive-Project/Cortex-Analyzers/pull/39) ([3c7](https://github.com/3c7))

**Closed issues:**

- File\_Info analyzer has problems examining pe files [\#38](https://github.com/TheHive-Project/Cortex-Analyzers/issues/38)
- Make cortexutils compatible with python 2 and 3 [\#35](https://github.com/TheHive-Project/Cortex-Analyzers/issues/35)
- Unify short template reports to use appropriate taxonomy [\#34](https://github.com/TheHive-Project/Cortex-Analyzers/issues/34)
- Virusshare.com analyzer [\#30](https://github.com/TheHive-Project/Cortex-Analyzers/issues/30)
- YARA Analyzer [\#19](https://github.com/TheHive-Project/Cortex-Analyzers/issues/19)
- Google Safe Browsing Analyzer [\#17](https://github.com/TheHive-Project/Cortex-Analyzers/issues/17)
- CIRCL.lu PassiveSSL Analyzer [\#12](https://github.com/TheHive-Project/Cortex-Analyzers/issues/12)
- CIRCL.lu PassiveDNS Analyzer [\#11](https://github.com/TheHive-Project/Cortex-Analyzers/issues/11)
- Nessus Analyzer [\#1](https://github.com/TheHive-Project/Cortex-Analyzers/issues/1)

**Merged pull requests:**

- Automatic ioc extraction using RegEx [\#40](https://github.com/TheHive-Project/Cortex-Analyzers/pull/40) ([3c7](https://github.com/3c7))
- Use StringIO.StringIO\(\) with python2 [\#36](https://github.com/TheHive-Project/Cortex-Analyzers/pull/36) ([3c7](https://github.com/3c7))

## [1.2.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.2.0) (2017-03-31)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.1.0...1.2.0)

**Closed issues:**

- OTXQuery : improve error handling [\#22](https://github.com/TheHive-Project/Cortex-Analyzers/issues/22)
- Analyzer Caching [\#6](https://github.com/TheHive-Project/Cortex-Analyzers/issues/6)
- Joe Sandbox Analyzer [\#27](https://github.com/TheHive-Project/Cortex-Analyzers/issues/27)
- MISP Analyzer [\#14](https://github.com/TheHive-Project/Cortex-Analyzers/issues/14)

**Merged pull requests:**

- Nessus Analyzer [\#20](https://github.com/TheHive-Project/Cortex-Analyzers/pull/20) ([guillomovitch](https://github.com/guillomovitch))

## [1.1.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.1.0) (2017-03-07)
[Full Changelog](https://github.com/TheHive-Project/Cortex-Analyzers/compare/1.0.0...1.1.0)

**Implemented enhancements:**

- Python \< 2.7 crashes on version check [\#10](https://github.com/TheHive-Project/Cortex-Analyzers/issues/10)
- VirusTotal GetReport can't get report for files from Cortex [\#9](https://github.com/TheHive-Project/Cortex-Analyzers/issues/9)
- Normalize analyzer's JSON configuration file [\#8](https://github.com/TheHive-Project/Cortex-Analyzers/issues/8)

**Fixed bugs:**

- OTX Query error when processing a file in Cortex  [\#21](https://github.com/TheHive-Project/Cortex-Analyzers/issues/21)
- VirusTotal GetReport can't get report for files from Cortex [\#9](https://github.com/TheHive-Project/Cortex-Analyzers/issues/9)

**Closed issues:**

- Analyzer Rate Limiting [\#5](https://github.com/TheHive-Project/Cortex-Analyzers/issues/5)
- Working on analyzers: CIRCL.lu PassiveSSL/DNS, CERT.AT PassiveDNS, MISP, IntelMQ, VMRay, Google Safebrowsing, URLQuery, yara [\#3](https://github.com/TheHive-Project/Cortex-Analyzers/issues/3)

## [1.0.0](https://github.com/TheHive-Project/Cortex-Analyzers/tree/1.0.0) (2017-02-17)
**Closed issues:**

-  "VirusTotal\_Scan" analyzer is not checking for TLP [\#2](https://github.com/TheHive-Project/Cortex-Analyzers/issues/2)



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*
