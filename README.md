# go-appsec/toolbox-sidenuclei

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-appsec/toolbox-sidenuclei/blob/main/LICENSE)
[![Tests - Main Push](https://github.com/go-appsec/toolbox-sidenuclei/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-appsec/toolbox-sidenuclei/actions/workflows/tests-main.yml)
[![Vibe-Scale 3.0(V2|U1|T1): Significant AI with gaps](https://img.shields.io/badge/Vibe--Scale%203.0(V2%7CU1%7CT1)-Significant%20AI%20with%20gaps-ffe066)](https://github.com/vibesdk/vibe-scale/blob/main/scale/vibe-3.md#v2-u1-t1-score-30--significant-ai-with-gaps)

**A passive [Nuclei](https://github.com/projectdiscovery/nuclei) scanning sidecar for [go-appsec/toolbox](https://github.com/go-appsec/toolbox).**

`toolbox-sidenuclei` is a pull-based observer that watches the traffic flows captured by sectool during a session. It automatically derives scan targets from observed endpoints, runs [Nuclei](https://github.com/projectdiscovery/nuclei) templates out-of-band, and files findings back as notes for the agent to review—providing automated vulnerability detection without interrupting the live probing flow.
