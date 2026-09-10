# Changelog

## [1.1.0](https://github.com/BeardedTinker/ha-wazuh-agent-addon/compare/v1.0.8...v1.1.0) (2026-09-10)


### Features

* release passwordless enrollment with deterministic builds ([#33](https://github.com/BeardedTinker/ha-wazuh-agent-addon/issues/33)) ([ea5fef5](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/ea5fef5ccf3374f4120c8917455e4e38b621ac69))


### Bug Fixes

* **ci:** validate add-on and all architectures ([ea5fef5](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/ea5fef5ccf3374f4120c8917455e4e38b621ac69))

## [1.0.8](https://github.com/BeardedTinker/ha-wazuh-agent-addon/compare/v1.0.7...v1.0.8) (2026-03-04)


### Bug Fixes

* machine-id is now restored, pulled or created ([cb933b5](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/cb933b5ca4caa1dce88a96ff0f1677b994a1b6da))
* machine-id is now restored, pulled or created ([5cad592](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/5cad5929c8d8d79fc27fc996a7cd71d02c491a17))

## [1.0.7](https://github.com/BeardedTinker/ha-wazuh-agent-addon/compare/v1.0.6...v1.0.7) (2026-03-04)


### Bug Fixes

* final fix ([3b82d30](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/3b82d303a187e09f262ba73a066cc7559718e2e0))
* final fix ([9b0335c](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/9b0335c2c1fc217a6de7b72c2d665a1c9ad672c1))

## [1.0.6](https://github.com/BeardedTinker/ha-wazuh-agent-addon/compare/v1.0.5...v1.0.6) (2026-03-04)


### Bug Fixes

* version ([26aea75](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/26aea755824a3cefc50de45ac73be284f71634be))

## [1.0.5](https://github.com/BeardedTinker/ha-wazuh-agent-addon/compare/v1.0.4...v1.0.5) (2026-03-04)


### Bug Fixes

* manual machine-id creation ([4670aeb](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/4670aebb3788eb817e6e341725de01f1321614fc))
* manual machine-id creation ([734c57e](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/734c57ed883102fdc78ad0b47e0fa2d382619b7b))

## [1.0.4](https://github.com/BeardedTinker/ha-wazuh-agent-addon/compare/v1.0.3...v1.0.4) (2026-03-04)


### Bug Fixes

* versioning ([6d08a59](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/6d08a5933cd7d8b8812aaf23bfc267f3f52fbc38))

## [1.0.3](https://github.com/BeardedTinker/ha-wazuh-agent-addon/compare/v1.0.2...v1.0.3) (2026-03-04)


### Bug Fixes

* fixing etc and machine-id in docker ([6190298](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/61902983bfd2130f0aee9032007f19e56646ed80))
* fixing etc and machine-id in docker ([705488d](https://github.com/BeardedTinker/ha-wazuh-agent-addon/commit/705488d4d7295ca74428a8906923a11e274d1851))

## 1.0.2

### Improvements
- Stabilized agent startup
- Improved persistent key handling

### Fixes
- Enrollment persistence issue

## 1.0.1

### Fixes
- Agent startup reliability

## 1.0.0

### Initial release
- Wazuh Agent for Home Assistant

## 0.3.0
- Production-grade release
- Persistent agent enrollment keys
- Auto-enrollment loop prevention
- Minimal security profile
- Journald-first log collection
- Configuration validation and hardening
- Documentation overhaul

## 0.2.x
- Initial public development
- Enrollment logic fixes
- Add-on storage handling
- Debug tooling

## 0.1.0
- Proof of concept
