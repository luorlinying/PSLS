
    // ===== Global state =====
    var pyBridge = null;
    var scanStartTime = null;
    var scanTimerInterval = null;
    var PROTECT_STORAGE_KEY = 'psls:protect:modules';
    var _strictModeSyncing = false;
    var _sandboxLargeFilesSyncing = false;
    // 跨扫描会话的累计统计（多次扫描累加，仅在程序重启时清零）
    // _currentScanScanned/_currentScanThreats 保存本次扫描会话的相对值，
    // 用于在 updateScanProgress 时叠加到累计值上展示，并在 onScanFinished 时正式合并。
    // _realtimeThreats 缓存实时防护累计威胁数（由 dashboardStatsUpdated 推送）。
    var _cumulativeScanned = 0;
    var _cumulativeThreats = 0;
    var _currentScanScanned = 0;
    var _currentScanThreats = 0;
    var _realtimeThreats = 0;

    // ===== Page navigation =====
    function navigateTo(pageName) {
      // 病毒库导入进行中时禁止离开当前页面
      if (_importInProgress && pageName !== 'tool-signatures') {
        if (typeof showInfoToast === 'function') {
          showInfoToast('提示', '导入进行中，请等待完成或停止导入', 'warning', 2000);
        }
        return;
      }
      document.querySelectorAll('.page').forEach(function(p) {
        p.style.display = 'none';
        p.classList.remove('active');
      });
      var target = document.getElementById('page-' + pageName);
      if (target) {
        target.style.display = 'flex';
        target.classList.add('active');
        // 目标页可能嵌套在其它 .page 容器内（终端主题 tools 页的详情面板），
        // 需逐级上溯把祖先容器一并显示，否则父级 display:none 会连带隐藏它。
        var anc = target.parentElement;
        while (anc) {
          if (anc.classList && anc.classList.contains('page')) {
            anc.style.display = 'flex';
            anc.classList.add('active');
          }
          anc = anc.parentElement;
        }
      }
      var navPageKey = pageName;
      if (pageName.indexOf('tool-') === 0) navPageKey = 'tools';
      // 导航选中态统一交给 CSS（.nav-link / .nav-link.active），
      // 避免 JS 写死主题色导致两套主题不一致。
      document.querySelectorAll('.nav-link').forEach(function(link) {
        link.classList.remove('active');
        link.style.background = '';
        link.style.color = '';
        link.style.opacity = '';
        var bar = link.querySelector('span.absolute');
        if (bar) bar.style.display = 'none';
      });
      document.querySelectorAll('.nav-link[data-page="' + navPageKey + '"]').forEach(function(link) {
        link.classList.add('active');
        var bar = link.querySelector('span.absolute');
        if (bar) bar.style.display = 'block';
      });
      if (window.lucide) lucide.createIcons();
      if (pageName === 'dashboard') updateDashboardBadge();
      if (pageName === 'protect') refreshProtectUI();
      if (pageName === 'tool-quarantine') { initQuarantinePage(); loadQuarantineList(); }
      if (pageName === 'tool-signatures') { initSignaturesPage(); loadSignatureSummary(); }
      if (pageName === 'tool-sigviewer') { initSigViewerPage(); loadSignatureViewer(); }
      if (pageName === 'tool-pe') { initPEPage(); resetPEAnalysis(); initHashPage(); resetHashCalculator(); }
      if (pageName === 'tool-sandbox') { initSandboxPage(); resetSandboxAnalysis(); }
      if (pageName === 'tool-logs') { initLogsPage(); loadLogs(); }
      if (pageName === 'tool-rollback') { initRollbackPage(); loadRollbackRecords(); }
      if (pageName === 'tool-mb') { initMBPage(); loadMBStatus(); }
      if (pageName === 'settings') { initToastScaleControl(); initSettingsButtons(); }
    }

    // ===== Sidebar click handlers =====
    document.querySelectorAll('.nav-link').forEach(function(link) {
      link.addEventListener('click', function(e) {
        e.preventDefault();
        var page = link.getAttribute('data-page');
        if (page) navigateTo(page);
      });
    });
    // 退出按钮：最小化到托盘（不真正退出）
    var navExit = document.getElementById('nav-exit');
    if (navExit) {
      navExit.addEventListener('click', function(e) {
        e.preventDefault();
        if (pyBridge && pyBridge.minimizeToTray) {
          pyBridge.minimizeToTray();
        }
      });
    }

    // ===== QWebChannel bridge =====
    function initBridge() {
      if (typeof QWebChannel !== 'undefined') {
        new QWebChannel(qt.webChannelTransport, function(channel) {
          pyBridge = channel.objects.pyBridge;
          onBridgeReady();
        });
      }
    }

    function onBridgeReady() {
      if (!pyBridge) return;
      // Connect signals — 所有复杂数据通过 JSON 字符串传递
      pyBridge.getInitialData.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) updateDashboardData(obj);
        } catch(e) { console.error('getInitialData parse error:', e, jsonStr); }
      });
      pyBridge.scanProgress.connect(function(scanned, total, threats) {
        updateScanProgress(scanned, total, threats);
      });
      // 主页指标卡统计更新（实时防护检测到威胁时推送）
      // Python 端仅推送实时防护累计威胁数（realtime_threats），
      // 前端负责合并：主页显示 = 扫描累计 + 本次扫描进行中 + 实时防护累计
      pyBridge.dashboardStatsUpdated.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) {
            var realtimeThreats = (typeof obj.realtime_threats === 'number') ? obj.realtime_threats : 0;
            _realtimeThreats = realtimeThreats;  // 缓存最新实时防护累计值
            var total = _cumulativeThreats + _currentScanThreats + _realtimeThreats;
            var threatsEl = document.getElementById('stat-threats');
            if (threatsEl) threatsEl.textContent = total;
          }
        } catch(e) { console.error('dashboardStatsUpdated parse error:', e, jsonStr); }
      });
      // MBR/引导扇区篡改告警 → 桌面结果弹窗
      pyBridge.mbrThreatDetected.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          var msg = (obj && obj.message) ? obj.message : '检测到引导扇区被篡改';
          var dev = (obj && obj.label) ? obj.label : '';
          showThreatResultToast({
            file_path: dev,
            result: { success: false, action: 'alert', message: msg }
          });
        } catch(e) { console.error('mbrThreatDetected parse error:', e, jsonStr); }
      });
      pyBridge.scanResultReceived.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj && obj.file_path) addScanResult(obj);
        } catch(e) { console.error('scanResultReceived parse error:', e, jsonStr); }
      });
      // 批量结果接收（性能优化）
      pyBridge.scanResultsBatch.connect(function(jsonStr) {
        try {
          var results = JSON.parse(jsonStr);
          if (Array.isArray(results)) {
            // 使用 requestAnimationFrame 延迟 DOM 操作，避免阻塞 JS 主线程
            // 修复：原来同步批量插入 DOM 会阻塞主线程，导致 setInterval(updateScanTimer) 延迟，
            // 扫描时间显示卡住。
            requestAnimationFrame(function() {
              var tbody = document.getElementById('scan-result-tbody');
              if (!tbody) return;
              var fragment = document.createDocumentFragment();
              var addedCount = 0;

              for (var i = 0; i < results.length; i++) {
                if (addScanResult(results[i], fragment)) {
                  addedCount++;
                }
              }

              if (addedCount > 0) {
                tbody.appendChild(fragment);
                // Auto-scroll once after batch insertion
                var container = tbody.closest('.psls-thin-scrollbar');
                if (container) container.scrollTop = container.scrollHeight;
              }
            });
          }
        } catch(e) { console.error('scanResultsBatch parse error:', e, jsonStr); }
      });
      pyBridge.scanFinished.connect(function(jsonStr) {
        try {
          console.log('[scanFinished] 收到信号:', jsonStr);
          var obj = JSON.parse(jsonStr);
          if (obj) onScanFinished(obj);
          else console.warn('[scanFinished] JSON 解析结果为 null');
        } catch(e) { console.error('scanFinished parse error:', e, jsonStr); }
      });
      // 主题切换被拒（持久化任务进行中）→ 提示用户
      pyBridge.themeSwitchBlocked.connect(function(msg) {
        if (typeof showInfoToast === 'function') {
          showInfoToast('外观', msg || '任务进行中，暂不可切换主题', 'warning', 4000);
        }
      });
      pyBridge.activityLogUpdated.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) updateActivityLog(obj);
        } catch(e) { console.error('activityLogUpdated parse error:', e, jsonStr); }
      });
      pyBridge.quarantineUpdated.connect(function(count) {
        updateQuarantineBadge(count);
      });
      pyBridge.signatureCountUpdated.connect(function(count) {
        updateSignatureBadge(count);
      });
      pyBridge.requestPage.connect(function(page) {
        navigateTo(page);
      });
      pyBridge.folderSelected.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj && obj.path) {
            var input = document.getElementById(obj.target || 'scan-path');
            if (input) input.value = obj.path;
            
            // 隔离区路径选择：调用后端设置新路径
            if (obj.target === 'quarantine-path-select' && pyBridge && pyBridge.setQuarantinePath) {
              var handleSetQResult = function(resultJson) {
                try {
                  var result = (typeof resultJson === 'string') ? JSON.parse(resultJson) : resultJson;
                  if (result.success) {
                    // 更新输入框显示
                    var quarantineInput = document.getElementById('quarantine-path');
                    if (quarantineInput) quarantineInput.value = result.new_path;
                    // 提示成功
                    if (typeof showInfoToast === 'function') {
                      var msg = result.migrated ? '已迁移隔离数据' : '路径已更新';
                      showInfoToast('隔离区路径', msg, 'success', 2000);
                    }
                  } else {
                    if (typeof showInfoToast === 'function') {
                      showInfoToast('隔离区路径', result.error || '设置失败', 'error', 3000);
                    }
                  }
                } catch (e) {
                  console.error('setQuarantinePath parse error:', e, resultJson);
                }
              };
              var qSetResult = pyBridge.setQuarantinePath(obj.path);
              if (qSetResult && typeof qSetResult.then === 'function') {
                qSetResult.then(handleSetQResult).catch(function(e) { console.error('setQuarantinePath failed:', e); });
              } else {
                handleSetQResult(qSetResult);
              }
            }
          }
        } catch(e) { console.error('folderSelected parse error:', e, jsonStr); }
      });
      // 威胁需要用户选择处理方式（已改为桌面弹窗，前端不再显示）
      pyBridge.threatActionRequired.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) {
            console.log('[threatActionRequired] 已由桌面弹窗处理', obj);
            // 实时防护发现需要处置的威胁 → 主界面盾牌标记"设备面临风险"
            if (obj.file_path) dashboardMarkThreatDetected(obj.file_path);
          }
        } catch(e) { console.error('threatActionRequired parse error:', e, jsonStr); }
      });
      // 威胁处理结果通知（已改为桌面弹窗，前端仅在未标记时显示 toast）
      pyBridge.threatActionResult.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj && obj.result && !obj.desktop_popup) {
            showThreatResultToast(obj);
            // 威胁处置完成 → 主界面盾牌解除"设备面临风险"
            if (obj.file_path) dashboardMarkThreatResolved(obj.file_path);
          } else {
            // 桌面弹窗处置的威胁同样解除盾牌风险状态
            if (obj && obj.file_path) dashboardMarkThreatResolved(obj.file_path);
          }
        } catch(e) { console.error('threatActionResult parse error:', e, jsonStr); }
      });
      // ===== 工具子页面信号连接 =====
      // 隔离区列表
      pyBridge.quarantineListReady.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) renderQuarantineList(obj);
        } catch(e) { console.error('quarantineListReady parse error:', e, jsonStr); }
      });
      // 隔离区批量操作结果（恢复/删除）
      pyBridge.quarantineBatchResult.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) {
            var type = obj.success ? 'success' : (obj.failed_count > 0 && obj.success_count > 0 ? 'warning' : 'danger');
            showInfoToast('隔离区操作', obj.message || '操作完成', type, obj.success ? 2000 : 3500);
            // 处置完成 → 清除主界面盾牌"设备面临风险"标记
            if (obj.success && typeof dashboardMarkThreatResolved === 'function') {
              dashboardMarkThreatResolved();
            }
            // 操作完成后刷新列表
            setTimeout(function() { loadQuarantineList(); }, 200);
          }
        } catch(e) { console.error('quarantineBatchResult parse error:', e, jsonStr); }
      });
      // 模块开关：后台构造/启停期间的"加载中"提示（避免用户以为没反应）
      try {
        if (pyBridge.moduleTogglePending) {
          pyBridge.moduleTogglePending.connect(function(jsonStr) {
            try {
              var o = JSON.parse(jsonStr) || {};
              showInfoToast('防护模块', (o.module || '模块') + ' 正在加载中…', 'info', 3000);
            } catch (e) {}
          });
        }
        if (pyBridge.moduleToggleSettled) {
          pyBridge.moduleToggleSettled.connect(function(jsonStr) {
            try {
              var o = JSON.parse(jsonStr) || {};
              var ok = (o.state === 'enabled');
              showInfoToast('防护模块', (o.module || '模块') + (ok ? ' 已启用' : ' 已关闭'),
                            ok ? 'success' : 'info', 2500);
            } catch (e) {}
          });
        }
      } catch (e) { console.warn('moduleToggle signals wiring failed:', e); }
      // 勒索文件回滚结果
      pyBridge.rollbackCompleted.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) handleRollbackCompleted(obj);
        } catch(e) { console.error('rollbackCompleted parse error:', e, jsonStr); }
      });
      // 签名库摘要
      pyBridge.signatureSummaryReady.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) renderSignatureSummary(obj);
        } catch(e) { console.error('signatureSummaryReady parse error:', e, jsonStr); }
      });
      // 病毒库查看列表
      pyBridge.signatureListReady.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) renderSignatureList(obj);
        } catch(e) { console.error('signatureListReady parse error:', e, jsonStr); }
      });
      // 病毒库删除结果
      pyBridge.signatureDeleteResult.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) handleSignatureDeleteResult(obj);
        } catch(e) { console.error('signatureDeleteResult parse error:', e, jsonStr); }
      });
      // 文件选择结果（target 决定回填到哪个输入框）
      pyBridge.fileSelected.connect(function(path, target) {
        handleFileSelected(path, target);
      });
      // 哈希计算结果
      pyBridge.hashResultReady.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) renderHashResult(obj);
        } catch(e) { console.error('hashResultReady parse error:', e, jsonStr); }
      });
      // PE 分析结果
      pyBridge.peAnalysisReady.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) renderPEAnalysis(obj);
        } catch(e) { console.error('peAnalysisReady parse error:', e, jsonStr); }
      });
      // 沙箱分析进度
      if (pyBridge.sandboxProgress) {
        pyBridge.sandboxProgress.connect(function(jsonStr) {
          try {
            var obj = JSON.parse(jsonStr);
            if (obj) updateSandboxProgress(obj);
          } catch(e) { console.error('sandboxProgress parse error:', e, jsonStr); }
        });
      }
      // 沙箱分析结果
      if (pyBridge.sandboxResultReady) {
        pyBridge.sandboxResultReady.connect(function(jsonStr) {
          try {
            var obj = JSON.parse(jsonStr);
            if (obj) renderSandboxResult(obj);
          } catch(e) { console.error('sandboxResultReady parse error:', e, jsonStr); }
        });
      }
      // 沙箱拦截结果 → 主界面盾牌标记"设备面临风险"（恶意/可疑且已隔离时自动解除，
      // 未隔离的威胁保持风险状态，由后续处置结果解除）
      if (pyBridge.sandboxBlocked) {
        pyBridge.sandboxBlocked.connect(function(jsonStr) {
          try {
            var obj = JSON.parse(jsonStr);
            if (obj && (obj.verdict === 'malware' || obj.verdict === 'suspicious') && obj.path) {
              if (obj.quarantined) {
                // 已自动隔离 → 威胁已被处置，直接解除风险状态
                dashboardMarkThreatResolved(obj.path);
              } else {
                dashboardMarkThreatDetected(obj.path);
              }
            }
          } catch(e) { console.error('sandboxBlocked parse error:', e, jsonStr); }
        });
      }
      // 签名库导入进度
      pyBridge.importProgress.connect(function(percent, message) {
        updateImportProgress(percent, message);
      });
      // 签名库导入完成
      pyBridge.importFinished.connect(function(added, total, success) {
        onImportFinished(added, total, success);
      });
      // MalwareBazaar 状态更新
      if (pyBridge.mbStatusUpdated) {
        pyBridge.mbStatusUpdated.connect(function(jsonStr) {
          try {
            var obj = JSON.parse(jsonStr);
            if (obj) handleMBStatus(obj);
          } catch(e) { console.error('mbStatusUpdated parse error:', e, jsonStr); }
        });
      }
      // MalwareBazaar 同步/训练进度
      if (pyBridge.mbSyncProgress) {
        pyBridge.mbSyncProgress.connect(function(jsonStr) {
          try {
            var obj = JSON.parse(jsonStr);
            if (obj) updateMBProgress(obj);
          } catch(e) { console.error('mbSyncProgress parse error:', e, jsonStr); }
        });
      }
      // MalwareBazaar 同步/训练结束
      if (pyBridge.mbSyncFinished) {
        pyBridge.mbSyncFinished.connect(function(jsonStr) {
          try {
            var obj = JSON.parse(jsonStr);
            if (obj) handleMBFinished(obj);
          } catch(e) { console.error('mbSyncFinished parse error:', e, jsonStr); }
        });
      }
      // 日志列表
      pyBridge.logsReady.connect(function(jsonStr) {
        try {
          var obj = JSON.parse(jsonStr);
          if (obj) renderLogs(obj);
        } catch(e) { console.error('logsReady parse error:', e, jsonStr); }
      });
      // 日志导出结果
      pyBridge.logsExported.connect(function(success) {
        onLogsExported(success);
      });
      // YARA 一键安装结果
      pyBridge.yaraInstallResult.connect(function(jsonStr) {
        try {
          var obj = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : jsonStr;
          if (obj) onYaraInstallResult(obj);
        } catch(e) { console.error('yaraInstallResult parse error:', e, jsonStr); }
      });
      // ML 引擎一键安装结果
      if (pyBridge.mlInstallResult) {
        pyBridge.mlInstallResult.connect(function(jsonStr) {
          try {
            var obj = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : jsonStr;
            if (obj) onMlInstallResult(obj);
          } catch(e) { console.error('mlInstallResult parse error:', e, jsonStr); }
        });
      }
      // ML 模型重新训练结果
      if (pyBridge.mlTrainResult) {
        pyBridge.mlTrainResult.connect(function(jsonStr) {
          try {
            var obj = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : jsonStr;
            if (obj) onMlTrainResult(obj);
          } catch(e) { console.error('mlTrainResult parse error:', e, jsonStr); }
        });
      }
      // 自我保护状态变化
      if (pyBridge.selfProtectionStatusChanged) {
        pyBridge.selfProtectionStatusChanged.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] selfProtectionStatusChanged:', jsonStr);
            // 直接用推送的数据更新 UI（不再轮询）
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            applySelfProtectionStatus(status);
          } catch(e) { console.error('selfProtectionStatusChanged error:', e, jsonStr); }
        });
      }
      // MBR / 引导扇区保护状态变化
      if (pyBridge.mbrProtectionStatusChanged) {
        pyBridge.mbrProtectionStatusChanged.connect(function(jsonStr) {
          try {
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            applyMbrProtectionStatus(status);
            if (document.getElementById('dashboard-shield')) updateDashboardBadge();
          } catch(e) { console.error('mbrProtectionStatusChanged error:', e, jsonStr); }
        });
      }
      // YARA 规则引擎状态推送
      if (pyBridge.ruleEngineStatusChanged) {
        pyBridge.ruleEngineStatusChanged.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] ruleEngineStatusChanged:', jsonStr);
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            applyYaraStatus(status);
          } catch(e) { console.error('ruleEngineStatusChanged error:', e, jsonStr); }
        });
      }
      // ML 引擎状态推送
      if (pyBridge.mlEngineStatusChanged) {
        pyBridge.mlEngineStatusChanged.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] mlEngineStatusChanged:', jsonStr);
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            applyMlStatus(status);
          } catch(e) { console.error('mlEngineStatusChanged error:', e, jsonStr); }
        });
      }
      // 严格模式状态推送
      if (pyBridge.strictModeStatusChanged) {
        pyBridge.strictModeStatusChanged.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] strictModeStatusChanged:', jsonStr);
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            applyStrictModeStatus(status);
          } catch(e) { console.error('strictModeStatusChanged error:', e, jsonStr); }
        });
      }
      // VirusIdentifier 开关状态推送（默认关闭；后端每轮广播，值变化时下发）
      if (pyBridge.virusIdentifierStatusChanged) {
        pyBridge.virusIdentifierStatusChanged.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] virusIdentifierStatusChanged:', jsonStr);
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            applyVirusIdentifierStatus(status);
          } catch(e) { console.error('virusIdentifierStatusChanged error:', e, jsonStr); }
        });
      }
      // 监测全部文件类型状态推送（严格模式启用时会自动开启此开关并推送通知）
      if (pyBridge.monitorAllFileTypesStatusChanged) {
        pyBridge.monitorAllFileTypesStatusChanged.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] monitorAllFileTypesStatusChanged:', jsonStr);
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            var toggle = document.getElementById('set-monitor-all-types');
            var label = document.getElementById('set-monitor-all-types-label');
            // 无论开启还是关闭，都同步UI状态（保持双向一致性）
            if (toggle) {
              var newChecked = !!status.enabled;
              if (toggle.checked !== newChecked) {
                _monitorAllTypesSyncing = true;
                toggle.checked = newChecked;
                applyToggleState(toggle.closest('.psls-toggle'), newChecked);
                _monitorAllTypesSyncing = false;
              }
            }
            if (label) {
              label.textContent = status.enabled ? '已启用' : '已关闭';
              label.style.color = status.enabled ? 'var(--psls-c-accent)' : 'var(--psls-c-gray-text)';
            }
            try { localStorage.setItem('psls:monitor-all-types', status.enabled ? '1' : '0'); } catch (e) {}
            // 如果是后端拒绝（success=false），展示原因toast
            if (typeof showInfoToast === 'function' && status && status.success === false && status.message) {
              showInfoToast('文件监测范围', status.message, 'warning', 3000);
            }
          } catch(e) { console.error('monitorAllFileTypesStatusChanged error:', e, jsonStr); }
        });
      }
      // 大文件沙箱分析开关状态推送
      if (pyBridge.sandboxRunLargeFilesStatusChanged) {
        pyBridge.sandboxRunLargeFilesStatusChanged.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] sandboxRunLargeFilesStatusChanged:', jsonStr);
            var status = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            var toggle = document.getElementById('set-sandbox-large-files');
            var label = document.getElementById('set-sandbox-large-files-label');
            if (toggle) {
              var newChecked = !!status.enabled;
              if (toggle.checked !== newChecked) {
                _sandboxLargeFilesSyncing = true;
                toggle.checked = newChecked;
                applyToggleState(toggle.closest('.psls-toggle'), newChecked);
                _sandboxLargeFilesSyncing = false;
              }
            }
            if (label) {
              label.textContent = status.enabled ? '已启用' : '已关闭';
              label.style.color = status.enabled ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
            }
            try { localStorage.setItem('psls:sandbox-large-files', status.enabled ? '1' : '0'); } catch (e) {}
          } catch(e) { console.error('sandboxRunLargeFilesStatusChanged error:', e, jsonStr); }
        });
      }
      // 白名单添加结果推送（单项/批量添加白名单后，通过信号接收结果显示Toast，避免依赖返回值）
      if (pyBridge.whitelistAddResult) {
        pyBridge.whitelistAddResult.connect(function(jsonStr) {
          try {
            console.log('[SIGNAL] whitelistAddResult:', jsonStr);
            var result = (typeof jsonStr === 'string') ? JSON.parse(jsonStr) : (jsonStr || {});
            if (!result || typeof showInfoToast !== 'function') return;
            var title = '添加到白名单';
            if (result.success) {
              var type = (result.skipped || (result.mode === 'batch' && result.added === 0 && result.failed === 0)) ? 'info' : 'success';
              showInfoToast(title, result.message || '操作完成', type, 2500);
              // 加入白名单即为已处置 → 清除主界面盾牌"设备面临风险"标记
              if (typeof dashboardMarkThreatResolved === 'function') {
                dashboardMarkThreatResolved();
              }
            } else {
              showInfoToast(title, result.message || '操作失败', 'warning', 3500);
            }
          } catch(e) { console.error('whitelistAddResult error:', e, jsonStr); }
        });
      }
      // ===== 初始状态同步（桥接就绪后立即同步所有设置）=====
      // 1. 同步声音开关状态
      var setSound = document.getElementById('set-sound');
      if (setSound) {
        pyBridge.setSoundEnabled(setSound.checked);
      }
      // 2. 同步所有防护模块状态
      var protectStates = loadProtectStates();
      var modules = document.querySelectorAll('[data-module]');
      modules.forEach(function(moduleEl) {
        var key = moduleEl.getAttribute('data-module');
        var input = moduleEl.querySelector('input[type="checkbox"]');
        if (input && key) {
          pyBridge.toggleModule(key, input.checked);
        }
      });
      // 3. 同步最大文件大小（扫描选项）
      var optSizeCb = document.getElementById('opt-max-size-unlimited');
      var optSlider = document.getElementById('opt-max-size');
      var isUnlimited = optSizeCb && optSizeCb.checked;
      var maxSizeBytes = 0;
      if (!isUnlimited && optSlider) {
        maxSizeBytes = (parseInt(optSlider.value, 10) || 50) * 1024 * 1024;
      }
      // 4. YARA/自我保护/严格模式状态完全依赖 Python 主动推送（信号机制）
      //    不再轮询，避免轮询返回错误状态覆盖信号推送的正确状态
      // 5. 同步实时监控范围配置
      try {
        if (pyBridge.getRealtimeScope) {
          var rawScope = pyBridge.getRealtimeScope();
          var scopeData = (typeof rawScope === 'string') ? JSON.parse(rawScope) : (rawScope || {});
          var scope = scopeData.scope || 'critical';
          var customPaths = scopeData.customPaths || [];
          // 同步到单选按钮
          var radios = document.querySelectorAll('.rt-scope-radio');
          for (var i = 0; i < radios.length; i++) {
            radios[i].checked = (radios[i].value === scope);
          }
          // 同步自定义路径
          _rtCustomPaths = customPaths.slice();
          renderRtPathList();
          // 显示/隐藏自定义路径区域
          var customBox = document.getElementById('rt-custom-paths');
          if (customBox) {
            customBox.style.display = (scope === 'custom') ? 'block' : 'none';
          }
        }
      } catch(e) {
        console.warn('获取实时监控范围失败:', e);
      }
      // 6. 同步扫描排除路径（QWebChannel 可能返回 Promise 或直接返回字符串）
      try {
        if (pyBridge.getScanExcludedPaths) {
          var rawExcl = pyBridge.getScanExcludedPaths();
          var applyExclData = function(exclData) {
            _scanExcludedPaths = (exclData.paths || []).slice();
            renderScanExcludeList();
          };
          if (rawExcl && typeof rawExcl.then === 'function') {
            rawExcl.then(function(raw) {
              var d = (typeof raw === 'string') ? JSON.parse(raw) : (raw || {});
              applyExclData(d);
            }).catch(function(e) { console.warn('获取扫描排除路径失败:', e); });
          } else {
            var exclData = (typeof rawExcl === 'string') ? JSON.parse(rawExcl) : (rawExcl || {});
            applyExclData(exclData);
          }
        }
      } catch(e) {
        console.warn('获取扫描排除路径失败:', e);
      }
      // 7. 同步隔离区路径
      try {
        if (pyBridge.getQuarantinePath) {
          var qResult = pyBridge.getQuarantinePath();
          var qInput = document.getElementById('quarantine-path');
          // QWebChannel 可能返回 Promise 或直接返回字符串，统一处理
          var setQPath = function(val) {
            if (qInput && val) {
              qInput.value = (typeof val === 'string') ? val : String(val);
            }
          };
          if (qResult && typeof qResult.then === 'function') {
            qResult.then(setQPath).catch(function(e) { console.warn('获取隔离区路径失败:', e); });
          } else {
            setQPath(qResult);
          }
        }
      } catch(e) {
        console.warn('获取隔离区路径失败:', e);
      }
      // 调试面板：桥接就绪后（此时才能问到弹窗清单）再渲染一次按钮
      try { pullDebugPopups(); } catch (e) { /* 忽略 */ }
      // Request initial data
      pyBridge.initRequested();
    }

    // ===== Dashboard updates =====
    function updateDashboardData(data) {
      if (!data) return;
      var scanned = document.getElementById('stat-scanned');
      var threats = document.getElementById('stat-threats');
      var sigs = document.getElementById('stat-signatures');
      // 初始数据：scanned 由前端累计计数器管理（后端恒为 0）；
      // threats 来自实时防护累计，缓存到 _realtimeThreats 并合并显示
      if (typeof data.threats === 'number') {
        _realtimeThreats = data.threats;
      }
      if (scanned) scanned.textContent = _cumulativeScanned.toLocaleString();
      if (threats) threats.textContent = (_cumulativeThreats + _realtimeThreats);
      if (sigs && typeof data.signatures === 'number') sigs.textContent = data.signatures.toLocaleString();
      if (typeof data.quarantineCount === 'number') updateQuarantineBadge(data.quarantineCount);
      if (typeof data.signatures === 'number') updateSignatureBadge(data.signatures);
      if (data.activities && data.activities.length > 0) updateActivityLog(data.activities);
      // 同步开机自启开关状态（以后端注册表实际状态为准）
      if (typeof data.autostartEnabled === 'boolean') {
        var autorunCb = document.getElementById('set-autorun');
        if (autorunCb) {
          autorunCb.checked = data.autostartEnabled;
          applyToggleState(autorunCb.closest('.psls-toggle'), data.autostartEnabled);
        }
      }
      // 同步"新文件扫描结果弹窗"开关状态（以后端为准）
      if (typeof data.newFileResultPopupEnabled === 'boolean') {
        var nfCb = document.getElementById('set-new-file-result-popup');
        if (nfCb) {
          nfCb.checked = data.newFileResultPopupEnabled;
          applyToggleState(nfCb.closest('.psls-toggle'), data.newFileResultPopupEnabled);
        }
      }
      // 同步威胁处理方式（后端为准）：设置页与扫描页两组下拉一起刷新，
      // 避免"设置页显示询问、扫描页显示自动处理"的不同步
      if (data.rtSuspiciousAction) syncThreatActionSelects('suspicious', data.rtSuspiciousAction);
      if (data.rtMalwareAction) syncThreatActionSelects('malware', data.rtMalwareAction);
    }

    // ===== 威胁处理方式：设置页与扫描页共用同一份设置 =====
    // 两组下拉历史互不相通：设置页（rt-*）走后端持久化，扫描页（opt-*）
    // 只有 HTML 静态默认、且不落盘，于是两页显示会不一致。现在统一：
    // 任意一处变更 -> 两处下拉同步 + 落 localStorage + 写后端同一字段。
    function _selectHasOption(el, value) {
      for (var i = 0; i < el.options.length; i++) {
        if (el.options[i].value === value) return true;
      }
      return false;
    }

    function syncThreatActionSelects(kind, value) {
      if (!value) return;
      ['rt-' + kind + '-action', 'opt-' + kind + '-action'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el && el.value !== value && _selectHasOption(el, value)) {
          el.value = value;
        }
      });
    }

    function onThreatActionChanged(kind, value) {
      syncThreatActionSelects(kind, value);
      try { localStorage.setItem('psls:rt-' + kind + '-action', value); } catch(e) {}
      if (pyBridge && typeof pyBridge.setRealtimeThreatAction === 'function') {
        pyBridge.setRealtimeThreatAction(kind, value);
      }
    }

    function bindThreatActionSelects() {
      ['suspicious', 'malware'].forEach(function(kind) {
        // 桥接就绪前先用本地缓存兜底（后端 getInitialData 稍后会覆盖）
        try {
          var saved = localStorage.getItem('psls:rt-' + kind + '-action');
          if (saved) syncThreatActionSelects(kind, saved);
        } catch(e) {}
        // 设置页与扫描页两处下拉绑定同一个处理函数
        ['rt-' + kind + '-action', 'opt-' + kind + '-action'].forEach(function(id) {
          var el = document.getElementById(id);
          if (!el || el.getAttribute('data-threat-action-bound')) return;
          el.setAttribute('data-threat-action-bound', '1');
          el.addEventListener('change', function() {
            onThreatActionChanged(kind, this.value);
          });
        });
      });
    }

    // 帮助标志点击：弹窗展示该日志的解决方案。
    // 用事件委托绑定（容器上监听一次），规避内联 onclick 被 CSP 禁用。
    function bindActivityHelp() {
      var container = document.getElementById('activity-log');
      if (!container) return;
      if (container.getAttribute('data-help-bound')) return;
      container.setAttribute('data-help-bound', '1');
      container.addEventListener('click', function(e) {
        var t = e.target;
        while (t && t !== container && !(t.classList && t.classList.contains('activity-help-btn'))) {
          t = t.parentNode;
        }
        if (!t || t === container) return;
        var raw = t.getAttribute('data-help');
        if (!raw) return;
        // 居中弹窗 + 右下角"知道了"按钮（与签名库导入格式说明弹窗一致）
        var footerHtml = '<button type="button" class="psls-btn psls-btn-primary">知道了</button>';
        var overlay = showModal('为什么驱动无法加载/MBR防护降级？', decodeURIComponent(raw), footerHtml);
        if (overlay) {
          var okBtn = overlay.querySelector('.modal-footer .psls-btn');
          if (okBtn) okBtn.addEventListener('click', function() { closeModal(overlay); });
        }
      });
    }

    function updateActivityLog(activities) {
      var container = document.getElementById('activity-log');
      if (!container || !activities || activities.length === 0) return;
      bindActivityHelp();
      container.innerHTML = '';
      activities.forEach(function(act) {
        var level = (act.level || 'INFO').toUpperCase();
        var status = act.status || '';
        var levelColor, levelBg;
        if (level === 'ERROR') {
          levelColor = 'var(--psls-danger)'; levelBg = 'var(--psls-c-danger-12)';
        } else if (level === 'WARN' || level === 'WARNING') {
          levelColor = 'var(--psls-warning)'; levelBg = 'var(--psls-c-warn-15)';
        } else {
          levelColor = 'var(--psls-primary)'; levelBg = 'var(--psls-c-accent-12)';
        }
        var statusColor, statusBg;
        if (status === '成功') { statusColor = 'var(--psls-c-success-text)'; statusBg = 'var(--psls-c-success-12)'; }
        else if (status === '警告' || status === '跳过') { statusColor = 'var(--psls-warning)'; statusBg = 'var(--psls-c-warn-15)'; }
        else if (status === '错误') { statusColor = 'var(--psls-danger)'; statusBg = 'var(--psls-c-danger-12)'; }
        else { statusColor = 'var(--psls-muted-foreground)'; statusBg = 'var(--psls-c-gray-18)'; }

        // 帮助标志："？"— 点击弹出该条日志的解决方案
        var hasHelp = act.help && String(act.help).trim().length > 0;
        var helpBtn = '';
        if (hasHelp) {
          // URL 编码 HTML 存入 data-help 属性，避免引号/尖括号破坏属性边界。
          // 不使用内联 onclick — QWebEngine CSP 默认禁止内联事件处理器。
          var encHelp = encodeURIComponent(String(act.help));
          helpBtn = '<a href="javascript:void(0)" class="activity-help-btn" style="flex-shrink:0;display:inline-flex;align-items:center;justify-content:center;'
            + 'width:20px;height:20px;margin-left:8px;border-radius:50%;background:var(--psls-c-accent-14);'
            + 'color:var(--psls-primary);font-size:12px;font-weight:700;text-decoration:none;cursor:pointer;'
            + 'border:1px solid var(--psls-border-soft);" '
            + 'data-help="' + encHelp + '" '
            + 'title="为什么驱动无法加载/MBR防护降级？">?</a>';
        }

        var row = document.createElement('div');
        row.className = 'flex items-center flex-1';
        row.style.cssText = 'padding:0 16px; font-size:11px; line-height:1.6; background:var(--psls-card); border-bottom:1px solid var(--psls-border-soft);';
        row.innerHTML =
          '<span style="width:150px; color:var(--psls-muted-foreground); flex-shrink:0;">' + escapeHtml(act.timestamp || '') + '</span>' +
          '<span style="width:44px; flex-shrink:0; margin-right:10px;"><span style="display:inline-block; width:36px; text-align:center; background:' + levelBg + '; color:' + levelColor + '; padding:1px 0; border-radius:4px; font-size:10px; font-weight:600;">' + level + '</span></span>' +
          '<span style="width:80px; flex-shrink:0; color:var(--psls-foreground); margin-right:10px;">' + escapeHtml(act.source || '') + '</span>' +
          '<span style="flex:1; color:var(--psls-foreground); min-width:0; word-break:break-all;">' + escapeHtml(act.message || '') + '</span>' +
          '<span style="display:flex; align-items:center; flex-shrink:0;">' + helpBtn
            + '<span style="background:' + statusBg + '; color:' + statusColor + '; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600;">' + escapeHtml(status) + '</span>'
          + '</span>';
        container.appendChild(row);
      });
      if (window.lucide) lucide.createIcons();
    }

    function updateQuarantineBadge(count) {
      var badge = document.getElementById('quarantine-badge');
      if (badge) badge.textContent = count + ' 个文件';
    }

    function updateSignatureBadge(count) {
      var badge = document.getElementById('signature-badge');
      if (badge) badge.textContent = (count || 0).toLocaleString() + ' 签名';
      var sigs = document.getElementById('stat-signatures');
      if (sigs && typeof count === 'number') sigs.textContent = count.toLocaleString();
      // 同步更新导入页面的恶意软件签名数
      var malwareEl = document.getElementById('sig-count-malware');
      if (malwareEl && typeof count === 'number') malwareEl.textContent = count.toLocaleString();
    }

    // ===== 统一状态面板颜色常量 =====
    var STATUS_COLORS = {
      green: { dot: 'var(--psls-c-success-dot)', text: 'var(--psls-c-success-text)', bg: 'var(--psls-c-success-12)' },
      yellow: { dot: 'var(--psls-c-warn-dot)', text: 'var(--psls-c-warn-text)', bg: 'var(--psls-c-warn-15)' },
      red: { dot: 'var(--psls-c-danger-dot)', text: 'var(--psls-c-danger-text)', bg: 'var(--psls-c-danger-12)' },
      gray: { dot: 'var(--psls-c-gray-dot)', text: 'var(--psls-c-gray-text)', bg: 'var(--psls-c-gray-12)' }
    };

    function setStatusRow(dotId, textId, state, text, labelId) {
      var c = STATUS_COLORS[state] || STATUS_COLORS.gray;
      var dot = document.getElementById(dotId);
      var txt = document.getElementById(textId);
      var lbl = labelId ? document.getElementById(labelId) : null;
      if (dot) dot.style.background = c.dot;
      if (txt) {
        txt.style.color = c.text;
        if (text !== undefined) txt.textContent = text;
      }
      if (lbl) lbl.style.color = c.text;
    }

    // ===== 主页保护状态汇总（统一渲染）=====
    // 全正常 → 单绿灯"所有保护组件正常运行"；有异常 → 列出所有异常项目；
    // 全部保护模块禁用 → 单红灯"所有保护模块全部禁用"。
    // 所有 apply/sync 函数把各自最新状态写入 window.pslsProtectionItems，
    // 由 refreshDashboardPanel 统一渲染主页面板与盾牌，避免多路 DOM 更新互相覆盖。
    window.pslsProtectionItems = {};
    var _dashPanelRafPending = false;
    var _dashRendering = false;   // render 期间写入缓存不触发再渲染，防递归
    var PROTECT_MODULE_LABELS = {
      'realtime-monitor': '实时防护',
      'process-protection': '进程保护',
      'file-protection': '文件保护',
      'system-protection': '系统保护',
      'autostart-protection': '启动项监测',
      'mbr-protection': 'MBR/关键目录保护'
    };
    var PROTECT_MODULE_KEYS = ['realtime-monitor', 'process-protection', 'file-protection',
                               'system-protection', 'autostart-protection', 'mbr-protection'];

    function dashSetItem(key, label, level, text) {
      if (!window.pslsProtectionItems) window.pslsProtectionItems = {};
      window.pslsProtectionItems[key] = { label: label, level: level, text: text };
      if (!_dashRendering) _scheduleDashRender();
    }
    function _scheduleDashRender() {
      if (_dashPanelRafPending) return;
      _dashPanelRafPending = true;
      requestAnimationFrame(function() {
        _dashPanelRafPending = false;
        refreshDashboardPanel();
      });
    }
    function _dashEscape(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function dashRowHtml(level, label, text) {
      var c = STATUS_COLORS[level] || STATUS_COLORS.gray;
      var txt = _dashEscape(label);
      if (text && text !== label) txt += '：' + _dashEscape(text);
      return '<div class="flex items-center gap-2">'
        + '<span style="width:8px;height:8px;border-radius:50%;background:' + c.dot + ';display:inline-block;"></span>'
        + '<span style="font-size:12px; color:' + c.text + '; font-weight:500;">' + txt + '</span>'
        + '</div>';
    }

    function refreshDashboardPanel() {
      var panel = document.getElementById('dashboard-status-panel');
      var itemsWrap = document.getElementById('dashboard-status-items');
      if (!panel || !itemsWrap) return;
      _dashRendering = true;
      try {
        var states = loadProtectStates();
        // 同步 6 个保护模块开关状态到 items
        // 仅显式关闭时强制红灯；开启且已有条目（如 MBR 降级黄灯）则保留原始状态，
        // 由各模块自己的 apply/sync 函数维护更细粒度信息
        PROTECT_MODULE_KEYS.forEach(function(k) {
          var lbl = PROTECT_MODULE_LABELS[k] || k;
          if (states[k] === false) {
            window.pslsProtectionItems[k] = { label: lbl, level: 'red', text: '已关闭' };
          } else if (!window.pslsProtectionItems[k]) {
            window.pslsProtectionItems[k] = { label: lbl, level: 'green', text: '已启用' };
          } else if (window.pslsProtectionItems[k].level === 'red') {
            // 该模块曾在本函数里被置为"已关闭"（红）。重新开启后必须立即恢复绿灯，
            // 否则关闭再开启时主页指示灯会残留红色、需手动刷新才更新。
            // 仅覆盖 level==='red' 的占位（即由"已关闭"置的红）；由模块自身维护的
            // 降级黄灯（如 MBR 驱动未加载）level 非 'red'，不会被覆盖。
            window.pslsProtectionItems[k] = { label: lbl, level: 'green', text: '已启用' };
          }
        });

        var items = window.pslsProtectionItems || {};
        var keys = Object.keys(items);
        var allModsOff = PROTECT_MODULE_KEYS.every(function(k) { return states[k] === false; });
        var allGreen = keys.length > 0 && keys.every(function(k) {
          return items[k] && items[k].level === 'green';
        });

        var html = '';
        var panelBg = STATUS_COLORS.green.bg;
        if (allModsOff) {
          html = dashRowHtml('red', '所有保护模块全部禁用');
          panelBg = STATUS_COLORS.red.bg;
        } else if (allGreen) {
          html = dashRowHtml('green', '所有保护组件正常运行');
          panelBg = STATUS_COLORS.green.bg;
        } else {
          var rows = [];
          keys.forEach(function(k) {
            var it = items[k];
            if (it && it.level !== 'green') rows.push(dashRowHtml(it.level, it.label || k, it.text));
          });
          html = rows.length ? rows.join('') : dashRowHtml('green', '所有保护组件正常运行');
          panelBg = STATUS_COLORS.yellow.bg;
        }
        itemsWrap.innerHTML = html;
        panel.style.background = panelBg;
      } finally {
        _dashRendering = false;
      }
      if (document.getElementById('dashboard-shield')) updateDashboardBadge();
    }

    // 活动威胁路径集合（存在未处置威胁 → 盾牌红×）
    // 扫描发现 malware/suspicious → 加入集合；威胁处置成功 → 移除
    window.pslsActiveThreatPaths = {};
    var _pslsBadgeRafPending = false;
    function _scheduleBadgeRefresh() {
      // rAF 合并：批量结果到达时仅在同一帧末刷新一次，避免高频 DOM 操作
      if (_pslsBadgeRafPending) return;
      _pslsBadgeRafPending = true;
      requestAnimationFrame(function() {
        _pslsBadgeRafPending = false;
        if (document.getElementById('dashboard-shield')) updateDashboardBadge();
      });
    }
    function dashboardMarkThreatDetected(path) {
      if (!path) return;
      window.pslsActiveThreatPaths[path] = true;
      _scheduleBadgeRefresh();
    }
    function dashboardMarkThreatResolved(path) {
      if (path) {
        // 优先精确匹配；未命中则大小写不敏感匹配（Windows 路径不区分大小写）
        if (window.pslsActiveThreatPaths[path]) {
          delete window.pslsActiveThreatPaths[path];
        } else {
          var lowerPath = String(path).toLowerCase();
          var matched = null;
          Object.keys(window.pslsActiveThreatPaths).forEach(function(k) {
            if (k && k.toLowerCase() === lowerPath) matched = k;
          });
          if (matched) delete window.pslsActiveThreatPaths[matched];
        }
      } else {
        window.pslsActiveThreatPaths = {};
      }
      _scheduleBadgeRefresh();
    }
    function updateDashboardBadge() {
      var states = loadProtectStates();
      var realtimeOn = states['realtime-monitor'] !== false;
      var title = document.getElementById('dashboard-hero-title');
      var subtitle = document.getElementById('dashboard-hero-subtitle');
      var shieldBg = document.getElementById('shield-bg');
      var shieldOutline = document.getElementById('shield-outline');
      var shieldMark = document.getElementById('shield-mark');
      var shieldDot = document.getElementById('shield-dot');
      var shieldSvg = document.getElementById('dashboard-shield');

      // 活动威胁优先：检测到威胁 → 红色 × 盾牌 + "设备面临风险"
      if (Object.keys(window.pslsActiveThreatPaths).length > 0) {
        title.textContent = '设备面临风险';
        subtitle.textContent = '检测到活动威胁，请及时处理';
        if (shieldBg) shieldBg.setAttribute('fill', 'var(--psls-c-danger-16)');
        if (shieldOutline) shieldOutline.setAttribute('stroke', 'var(--psls-c-danger-dot)');
        if (shieldMark) {
          shieldMark.setAttribute('stroke', 'var(--psls-c-danger-dot)');
          shieldMark.setAttribute('stroke-width', '2');
          shieldMark.setAttribute('d', 'M9 9l6 6M15 9l-6 6');
        }
        if (shieldDot) shieldDot.style.display = 'none';
        if (shieldSvg) shieldSvg.style.filter = 'drop-shadow(0 0 8px var(--psls-c-danger-45))';
        if (window.lucide) lucide.createIcons();
        return;
      }

      // 全部保护模块禁用 → 红色 × 盾牌 + "保护已禁用"
      if (PROTECT_MODULE_KEYS.every(function(k) { return states[k] === false; })) {
        title.textContent = '保护已禁用';
        subtitle.textContent = '所有保护均已禁用，建议尽快开启';
        if (shieldBg) shieldBg.setAttribute('fill', 'var(--psls-c-danger-16)');
        if (shieldOutline) shieldOutline.setAttribute('stroke', 'var(--psls-c-danger-dot)');
        if (shieldMark) {
          shieldMark.setAttribute('stroke', 'var(--psls-c-danger-dot)');
          shieldMark.setAttribute('stroke-width', '2');
          shieldMark.setAttribute('d', 'M9 9l6 6M15 9l-6 6');
        }
        if (shieldDot) shieldDot.style.display = 'none';
        if (shieldSvg) shieldSvg.style.filter = 'drop-shadow(0 0 8px var(--psls-c-danger-45))';
        if (window.lucide) lucide.createIcons();
        return;
      }

      // 存在异常/降级/未检测项目 → 黄色感叹号盾牌 + "保护未完全启用"
      var items = window.pslsProtectionItems || {};
      var keys = Object.keys(items);
      var anyBad = keys.some(function(k) { return items[k] && items[k].level !== 'green'; }) || !realtimeOn;
      if (anyBad) {
        title.textContent = '保护未完全启用';
        subtitle.textContent = '有部分防护模块未开启，建议尽快开启';
        if (shieldBg) shieldBg.setAttribute('fill', 'var(--psls-warning)');
        if (shieldOutline) shieldOutline.setAttribute('stroke', 'var(--psls-warning)');
        if (shieldMark) {
          shieldMark.setAttribute('stroke', 'var(--psls-warning)');
          shieldMark.setAttribute('stroke-width', '2.2');
          shieldMark.setAttribute('d', 'M12 8v5');
        }
        if (shieldDot) {
          shieldDot.setAttribute('fill', 'var(--psls-warning)');
          shieldDot.style.display = '';
        }
        if (shieldSvg) shieldSvg.style.filter = 'drop-shadow(0 0 8px var(--psls-c-warn-40))';
        if (window.lucide) lucide.createIcons();
        return;
      }

      // 全部正常 → 绿色盾牌 ✓ + "设备已保护"
      title.textContent = '设备已保护';
      subtitle.textContent = '系统安全状态良好';
      if (shieldBg) shieldBg.setAttribute('fill', 'var(--psls-primary)');
      if (shieldOutline) shieldOutline.setAttribute('stroke', 'var(--psls-primary)');
      if (shieldMark) {
        shieldMark.setAttribute('stroke', 'var(--psls-primary)');
        shieldMark.setAttribute('stroke-width', '2');
        shieldMark.setAttribute('d', 'M8.5 12l2.5 2.5 4.5-5');
      }
      if (shieldDot) shieldDot.style.display = 'none';
      if (shieldSvg) shieldSvg.style.filter = '';
      if (window.lucide) lucide.createIcons();
    }

    // ===== Scan logic =====
    // 最大文件大小同步（两处：扫描页滑块、设置页数字）
    // 签名库导入配置的"最大文件大小"独立，不参与同步
    // 滑块最大值(1024)表示"无限制"，与复选框联动
    var MAX_SIZE_SLIDER_MAX = 1024;

    function updateMaxSizeUI(size, unlimited) {
      var slider = document.getElementById('opt-max-size');
      var sliderVal = document.getElementById('opt-max-size-value');
      var sliderCb = document.getElementById('opt-max-size-unlimited');
      var setInput = document.getElementById('set-max-size');
      var setCb = document.getElementById('set-max-size-unlimited');

      var isUnlimited = !!unlimited;
      var display = isUnlimited ? '无限制' : (size + ' MB');

      if (slider) {
        slider.disabled = isUnlimited;
        if (isUnlimited) {
          slider.value = MAX_SIZE_SLIDER_MAX;
        } else {
          slider.value = Math.min(Math.max(size, 1), MAX_SIZE_SLIDER_MAX - 1);
        }
        if (sliderVal) sliderVal.textContent = display;
        if (sliderCb) sliderCb.checked = isUnlimited;
      }
      if (setInput) {
        setInput.disabled = isUnlimited;
        if (isUnlimited) {
          setInput.value = MAX_SIZE_SLIDER_MAX;
        } else {
          setInput.value = Math.min(Math.max(size, 1), MAX_SIZE_SLIDER_MAX - 1);
        }
      }
      if (setCb) setCb.checked = isUnlimited;
    }

    function updateMaxSizeFromSlider(slider) {
      var rawVal = parseInt(slider.value, 10) || 50;
      // 滑块拖到最大值时视为无限制
      if (rawVal >= MAX_SIZE_SLIDER_MAX) {
        updateMaxSizeUI(MAX_SIZE_SLIDER_MAX, true);
      } else {
        updateMaxSizeUI(rawVal, false);
      }
    }

    function getMaxSizeFromUI() {
      var slider = document.getElementById('opt-max-size');
      var unlimited = document.getElementById('opt-max-size-unlimited');
      if (unlimited && unlimited.checked) return 0;
      var val = parseInt(slider ? slider.value : '50', 10) || 50;
      // 如果滑块正好在最大值，也视为无限制
      if (val >= MAX_SIZE_SLIDER_MAX) return 0;
      return val;
    }

    function getScanOptions() {
      return {
        scanAll: document.getElementById('opt-scan-all').checked,
        scanArchives: document.getElementById('opt-scan-archives').checked,
        exeOnly: document.getElementById('opt-exe-only').checked,
        maxSize: getMaxSizeFromUI(),
        notifyThreat: document.getElementById('opt-notify-threat').checked,
        suspiciousAction: document.getElementById('opt-suspicious-action').value,
        malwareAction: document.getElementById('opt-malware-action').value,
        archiveDepth: parseInt(document.getElementById('opt-archive-depth').value, 10) || 3
      };
    }

    function updateArchiveDepthFromSlider(slider) {
      var val = parseInt(slider.value, 10);
      var label = document.getElementById('opt-archive-depth-value');
      if (label) {
        label.textContent = val + ' 层';
      }
    }

    function startQuickScan() {
      if (!pyBridge) return;
      var options = getScanOptions();
      pyBridge.startQuickScan(options);
      setupScanUI();
    }

    function startCustomScan() {
      if (!pyBridge) return;
      var pathInput = document.getElementById('scan-path');
      var options = getScanOptions();
      options.path = pathInput ? pathInput.value : 'C:/';
      pyBridge.startCustomScan(options);
      setupScanUI();
    }

    function lockScanOptions() {
      var optIds = [
        'opt-scan-all', 'opt-scan-archives', 'opt-exe-only',
        'opt-notify-threat', 'opt-suspicious-action', 'opt-malware-action',
        'opt-max-size', 'opt-max-size-unlimited', 'opt-archive-depth'
      ];
      optIds.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
          el.disabled = true;
          if (el.type === 'checkbox' || el.type === 'range') {
            el.style.cursor = 'not-allowed';
          }
        }
      });
      var selects = ['opt-suspicious-action', 'opt-malware-action'];
      selects.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
          el.style.cursor = 'not-allowed';
          el.style.opacity = '0.7';
        }
      });
      var labels = document.querySelectorAll('.psls-toggle input:disabled + .psls-toggle-track, .psls-toggle input:disabled + .psls-toggle-track + .psls-toggle-thumb');
    }

    function unlockScanOptions() {
      var optIds = [
        'opt-scan-all', 'opt-scan-archives', 'opt-exe-only',
        'opt-notify-threat', 'opt-suspicious-action', 'opt-malware-action',
        'opt-max-size', 'opt-max-size-unlimited', 'opt-archive-depth'
      ];
      optIds.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
          el.disabled = false;
          if (el.type === 'checkbox' || el.type === 'range') {
            el.style.cursor = '';
          }
        }
      });
      var selects = ['opt-suspicious-action', 'opt-malware-action'];
      selects.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
          el.style.cursor = '';
          el.style.opacity = '';
        }
      });
    }

    function setupScanUI() {
      scanStartTime = Date.now();
      // 标记扫描进行中：主题切换会整页重载入口 HTML 并丢失 JS 状态，
      // 主题入口据此在扫描期间禁止切换（后端 setTheme 亦会硬拦截）。
      window.__pslsScanActive = true;
      lockScanOptions();
      var quickBtn = document.getElementById('btn-quick-scan');
      var customBtn = document.getElementById('btn-custom-scan');
      var stopBtn = document.getElementById('btn-stop-scan');
      var bar = document.getElementById('scan-progress-bar');
      if (quickBtn) { quickBtn.disabled = true; quickBtn.textContent = '扫描中...'; }
      if (customBtn) { customBtn.disabled = true; customBtn.textContent = '扫描中...'; }
      if (stopBtn) stopBtn.style.display = 'inline-flex';
      // Reset stats
      if (document.getElementById('scan-stat-scanned')) document.getElementById('scan-stat-scanned').textContent = '0';
      if (document.getElementById('scan-stat-threats')) document.getElementById('scan-stat-threats').textContent = '0';
      if (document.getElementById('scan-stat-time')) document.getElementById('scan-stat-time').textContent = '00:00';
      if (bar) { bar.style.width = '100%'; bar.style.background = 'linear-gradient(90deg, var(--psls-primary) 0%, var(--psls-primary-tint-strong) 50%, var(--psls-primary) 100%)'; bar.style.backgroundSize = '200% 100%'; bar.style.animation = 'psls-progress-indeterminate 1.5s ease-in-out infinite'; }
      if (document.getElementById('scan-progress-text')) document.getElementById('scan-progress-text').textContent = '统计中...';
      // Create result table
      createScanResultTable();
      // Start timer（使用 requestAnimationFrame 避免被批量 DOM 操作阻塞）
      if (scanTimerInterval) { clearInterval(scanTimerInterval); scanTimerInterval = null; }
      scanTimerInterval = setInterval(function() {
        requestAnimationFrame(updateScanTimer);
      }, 1000);
    }

    function updateScanTimer() {
      if (!scanStartTime) return;
      var elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
      var mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
      var secs = String(elapsed % 60).padStart(2, '0');
      var timeEl = document.getElementById('scan-stat-time');
      if (timeEl) timeEl.textContent = mins + ':' + secs;
    }

    function createScanResultTable() {
      var container = document.getElementById('scan-results-container');
      if (!container) return;
      container.innerHTML = '';
      var wrap = document.createElement('div');
      wrap.className = 'flex-1 flex flex-col overflow-hidden';
      wrap.style.minHeight = '0';
      wrap.innerHTML =
        '<div style="overflow-y:auto; flex:1;" class="psls-thin-scrollbar">' +
          '<table class="data-table">' +
            '<thead><tr>' +
              '<th>文件路径</th><th>状态</th><th>签名</th>' +
            '</tr></thead>' +
            '<tbody id="scan-result-tbody"></tbody>' +
          '</table>' +
        '</div>';
      container.appendChild(wrap);
    }

    // ===== Threat Notification Toast =====
    var _toastSeq = 0;

    function showThreatNotification(threat) {
      var container = document.getElementById('threat-toast-container');
      if (!container) return;
      var isDanger = (threat.status === 'malware');
      var headerClass = isDanger ? 'danger' : 'warning';
      var title = isDanger ? '检测到危险对象' : '检测到可疑对象';
      var toastId = 'toast-' + (++_toastSeq);

      var toast = document.createElement('div');
      toast.className = 'threat-toast';
      toast.id = toastId;
      _applyToastScale(toast);
      toast.innerHTML =
        '<div class="threat-toast-header ' + headerClass + '">' +
          '<span>' + title + '</span>' +
        '</div>' +
        '<div class="threat-toast-body">' +
          '<div>' + escapeHtml(threat.signature_name || '未知威胁') + '</div>' +
          '<div class="file-path">' + escapeHtml(threat.file_path || '') + '</div>' +
        '</div>' +
        '<div class="threat-toast-actions">' +
          '<button class="threat-toast-btn threat-toast-btn-danger" data-action="auto">' + (isDanger ? '隔离/删除' : '自动处理') + '</button>' +
          '<button class="threat-toast-btn threat-toast-btn-secondary" data-action="ignore">忽略</button>' +
        '</div>';
      container.appendChild(toast);

      // 绑定按钮
      var autoBtn = toast.querySelector('[data-action="auto"]');
      var ignoreBtn = toast.querySelector('[data-action="ignore"]');
      if (autoBtn) autoBtn.addEventListener('click', function() {
        if (pyBridge) {
          pyBridge.processThreat(JSON.stringify({
            file_path: threat.file_path,
            status: threat.status,
            signature_name: threat.signature_name,
            action: 'auto'
          }));
        }
        removeToast(toastId);
      });
      if (ignoreBtn) ignoreBtn.addEventListener('click', function() {
        if (pyBridge) {
          pyBridge.processThreat(JSON.stringify({
            file_path: threat.file_path,
            status: threat.status,
            signature_name: threat.signature_name,
            action: 'ignore'
          }));
        }
        removeToast(toastId);
      });

      // 30秒自动关闭
      setTimeout(function() { removeToast(toastId); }, 30000);
    }

    function showThreatResultToast(data) {
      var container = document.getElementById('threat-toast-container');
      if (!container) return;
      var result = data.result || {};
      var success = result.success;
      var action = result.action || '';
      var message = result.message || '';
      var headerClass = success ? 'success' : 'info';
      var icon = success ? '✓' : '✗';
      var title = '处理结果';

      var toastId = 'toast-' + (++_toastSeq);
      var toast = document.createElement('div');
      toast.className = 'threat-toast';
      toast.id = toastId;
      _applyToastScale(toast);
      toast.innerHTML =
        '<div class="threat-toast-header ' + headerClass + '">' +
          '<span style="font-size:16px;">' + icon + '</span>' +
          '<span>' + title + '</span>' +
        '</div>' +
        '<div class="threat-toast-body">' +
          '<div style="font-weight:500;">' + escapeHtml(message) + '</div>' +
          '<div class="file-path">' + escapeHtml(data.file_path || '') + '</div>' +
        '</div>';
      container.appendChild(toast);
      setTimeout(function() { removeToast(toastId); }, 8000);
    }

    function removeToast(toastId) {
      var toast = document.getElementById(toastId);
      if (!toast) return;
      toast.classList.add('removing');
      setTimeout(function() {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 300);
    }

    function addScanResult(result, batchContainer) {
      if (!result) return null;
      var status = result.status || 'clean';
      // statusKey 用于筛选：恶意/可疑保持独立（计数统一为"威胁"，但分类选项分离）
      var statusKey = status;
      if (status === 'warning' || status === 'error') statusKey = 'warning';
      else if (status !== 'malware' && status !== 'suspicious') statusKey = 'safe';

      var statusText, badgeClass;
      if (status === 'malware') { statusText = '恶意'; badgeClass = 'badge-danger'; }
      else if (status === 'suspicious') { statusText = '可疑'; badgeClass = 'badge-warning'; }
      else if (status === 'warning') { statusText = '警告'; badgeClass = 'badge-warning'; }
      else if (status === 'error') { statusText = '错误'; badgeClass = 'badge-warning'; }
      else { statusText = '安全'; badgeClass = 'badge-safe'; }

      // 扫描发现恶意/可疑威胁 → 主界面盾牌标记为"设备面临风险"
      if (status === 'malware' || status === 'suspicious') {
        dashboardMarkThreatDetected(result.file_path || result.path || '');
      }

      var tr = document.createElement('tr');
      tr.setAttribute('data-status', statusKey);
      tr.innerHTML =
        '<td style="font-family:var(--psls-font-mono); font-size:11px; word-break:break-all;">' + escapeHtml(result.file_path || result.path || '') + '</td>' +
        '<td><span class="badge ' + badgeClass + '">' + statusText + '</span></td>' +
        '<td style="font-size:11px; color:var(--psls-muted-foreground);">' + escapeHtml(result.signature_name || result.signature || '-') + '</td>';
      
      if (batchContainer) {
        // 批量模式：加入到容器，由外层统一处理插入
        var filter = document.getElementById('scan-result-filter');
        var filterVal = filter ? filter.value : 'all';
        if (filterVal !== 'all' && filterVal !== statusKey) return null;
        batchContainer.appendChild(tr);
        return tr;
      } else {
        // 单条模式：直接插入
        var tbody = document.getElementById('scan-result-tbody');
        if (!tbody) return null;
        var filter = document.getElementById('scan-result-filter');
        var filterVal = filter ? filter.value : 'all';
        if (filterVal !== 'all' && filterVal !== statusKey) return null;
        tbody.appendChild(tr);
        // Auto-scroll to bottom
        var container = tbody.closest('.psls-thin-scrollbar');
        if (container) container.scrollTop = container.scrollHeight;
        return tr;
      }
    }

    function updateScanProgress(scanned, total, threats) {
      var scanEl = document.getElementById('scan-stat-scanned');
      var threatEl = document.getElementById('scan-stat-threats');
      var bar = document.getElementById('scan-progress-bar');
      var text = document.getElementById('scan-progress-text');
      var actualScanned = Math.max(0, scanned) || 0;
      var actualThreats = threats || 0;
      // 保存本次扫描的相对值，供主页指标卡叠加展示与 onScanFinished 合并使用
      _currentScanScanned = actualScanned;
      _currentScanThreats = actualThreats;
      // 扫描页统计显示本次扫描的相对值
      if (scanEl) scanEl.textContent = actualScanned.toLocaleString();
      if (threatEl) threatEl.textContent = actualThreats;

      // 同步更新主页指标卡：使用累计值 + 本次值 + 实时防护累计，保证多次扫描间累加不重置
      var dashScanned = document.getElementById('stat-scanned');
      var dashThreats = document.getElementById('stat-threats');
      if (dashScanned && total > 0) dashScanned.textContent = (_cumulativeScanned + actualScanned).toLocaleString();
      if (dashThreats && total > 0) dashThreats.textContent = (_cumulativeThreats + actualThreats + _realtimeThreats);

      // 统计阶段：total = -1，scanned 为负数表示已统计的文件数
      if (total === -1 || total < 0) {
        if (bar) {
          bar.style.width = '100%';
          bar.style.background = 'linear-gradient(90deg, var(--psls-primary) 0%, var(--psls-primary-tint-strong) 50%, var(--psls-primary) 100%)';
          bar.style.backgroundSize = '200% 100%';
          bar.style.animation = 'psls-progress-indeterminate 1.5s ease-in-out infinite';
        }
        if (text) text.textContent = '统计中... (' + Math.abs(scanned) + ')';
        return;
      }

      // 正常扫描阶段
      var pct = 0;
      if (total && total > 0) {
        pct = Math.min(100, Math.round((Math.max(0, scanned) / total) * 100));
      }
      if (bar) {
        bar.style.width = pct + '%';
        bar.style.background = 'var(--psls-primary)';
        bar.style.animation = '';
      }
      if (text) text.textContent = pct + '%';
    }

    function onScanFinished(stats) {
      window.__pslsScanActive = false;   // 扫描结束：解除主题切换限制
      unlockScanOptions();
      // 取消 stopScan 设置的兜底定时器（正常流程已到达）
      if (_stopFallbackTimer) { clearTimeout(_stopFallbackTimer); _stopFallbackTimer = null; }
      if (scanTimerInterval) { clearInterval(scanTimerInterval); scanTimerInterval = null; }
      var quickBtn = document.getElementById('btn-quick-scan');
      var customBtn = document.getElementById('btn-custom-scan');
      var stopBtn = document.getElementById('btn-stop-scan');
      var bar = document.getElementById('scan-progress-bar');
      var text = document.getElementById('scan-progress-text');
      if (quickBtn) { quickBtn.disabled = false; quickBtn.textContent = '开始快速扫描'; }
      if (customBtn) { customBtn.disabled = false; customBtn.textContent = '开始扫描'; }
      if (stopBtn) { stopBtn.textContent = '停止扫描'; stopBtn.style.display = 'none'; }
      if (bar) { bar.style.animation = ''; bar.style.background = 'var(--psls-primary)'; }
      if (stats) {
        var scanned = stats.scanned || 0;
        var total = stats.total || 0;
        var threats = stats.threats || 0;
        // 本次扫描会话结束：将本次最终值并入累计值（不重置累计）
        // 使用 stats 的权威值，避免 updateScanProgress 中途值导致的偏差
        _cumulativeScanned += scanned;
        _cumulativeThreats += threats;
        // 重置本次扫描相对值，为下一次扫描做准备
        _currentScanScanned = 0;
        _currentScanThreats = 0;
        // 扫描页统计显示本次扫描的最终值
        if (document.getElementById('scan-stat-scanned')) document.getElementById('scan-stat-scanned').textContent = scanned.toLocaleString();
        if (document.getElementById('scan-stat-threats')) document.getElementById('scan-stat-threats').textContent = threats;
        // 主页指标卡显示累计值（多次扫描累加 + 实时防护累计，不重置）
        if (document.getElementById('stat-scanned')) document.getElementById('stat-scanned').textContent = _cumulativeScanned.toLocaleString();
        if (document.getElementById('stat-threats')) document.getElementById('stat-threats').textContent = (_cumulativeThreats + _realtimeThreats);
        var pct = 0;
        if (total && total > 0) {
          // 未完成时向下取整，避免 99.x% 被四舍五入成"100% 完成"的假象
          pct = stats.incomplete
            ? Math.floor((scanned / total) * 100)
            : Math.min(100, Math.round((scanned / total) * 100));
        }
        if (bar) bar.style.width = pct + '%';
        if (stats.incomplete) {
          // 诚实上报：扫描进程异常导致部分文件未扫描，不谎报 100%
          var miss = (typeof stats.unscanned === 'number')
            ? stats.unscanned : Math.max(0, total - scanned);
          if (text) text.textContent = '未完成 ' + scanned.toLocaleString() + '/' + total.toLocaleString();
          if (typeof showInfoToast === 'function') {
            showInfoToast('扫描未完成',
              '扫描进程异常，' + miss + ' 个文件未扫描，建议重新扫描', 'error', 6000);
          }
        } else if (text) {
          text.textContent = pct + '%';
        }
      }
    }

    var _stopFallbackTimer = null;

    function stopScan() {
      var stopBtn = document.getElementById('btn-stop-scan');
      var quickBtn = document.getElementById('btn-quick-scan');
      var customBtn = document.getElementById('btn-custom-scan');
      if (stopBtn) stopBtn.textContent = '停止中...';
      if (quickBtn) quickBtn.disabled = true;
      if (customBtn) customBtn.disabled = true;

      // 清理上一次未触发的兜底定时器
      if (_stopFallbackTimer) { clearTimeout(_stopFallbackTimer); _stopFallbackTimer = null; }

      // 5 秒兜底：如果 scanFinished 没有到达，强制恢复 UI
      _stopFallbackTimer = setTimeout(function() {
        var sb = document.getElementById('btn-stop-scan');
        if (sb && sb.textContent === '停止中...') {
          console.warn('[stopScan fallback] scanFinished 未按时到达，强制恢复 UI');
          window.__pslsScanActive = false;
          unlockScanOptions();
          var qb = document.getElementById('btn-quick-scan');
          var cb = document.getElementById('btn-custom-scan');
          if (qb) { qb.disabled = false; qb.textContent = '开始快速扫描'; }
          if (cb) { cb.disabled = false; cb.textContent = '开始扫描'; }
          sb.textContent = '停止扫描';
          sb.style.display = 'none';
          if (scanTimerInterval) { clearInterval(scanTimerInterval); scanTimerInterval = null; }
          var bar = document.getElementById('scan-progress-bar');
          var text = document.getElementById('scan-progress-text');
          if (bar) { bar.style.animation = ''; bar.style.background = 'var(--psls-primary)'; }
          if (text) text.textContent = '已停止';
        }
        _stopFallbackTimer = null;
      }, 5000);

      if (!pyBridge) {
        console.warn('[stopScan] pyBridge 尚未就绪，已设置兜底超时');
        return;
      }
      try {
        pyBridge.stopScan();
      } catch (e) {
        console.error('[stopScan] 调用 pyBridge.stopScan 失败:', e);
      }
    }

    // ===== Protect module logic =====
    function loadProtectStates() {
      try {
        var raw = localStorage.getItem(PROTECT_STORAGE_KEY);
        if (raw) {
          var saved = JSON.parse(raw);
          // 合并默认值：新模块键缺失时按默认启用，避免旧存档导致新功能意外关闭
          var merged = {
            'realtime-monitor': true,
            'process-protection': true,
            'file-protection': true,
            'system-protection': true,
            'autostart-protection': true,
            'mbr-protection': true,
            'visual-prank': true,
            'notification': true
          };
          for (var k in saved) { if (Object.prototype.hasOwnProperty.call(saved, k)) merged[k] = saved[k]; }
          return merged;
        }
      } catch (e) {}
      return {
        'realtime-monitor': true,
        'process-protection': true,
        'file-protection': true,
        'system-protection': true,
        'autostart-protection': true,
        'mbr-protection': true,
        'visual-prank': true,
        'notification': true
      };
    }

    function saveProtectStates(states) {
      try { localStorage.setItem(PROTECT_STORAGE_KEY, JSON.stringify(states)); } catch (e) {}
    }

    function updateModuleStatus(moduleEl, enabled) {
      var badge = moduleEl.querySelector('.module-status');
      if (!badge) return;
      if (enabled) {
        badge.style.backgroundColor = 'var(--psls-c-success-12)';
        badge.style.color = 'var(--psls-c-success-text)';
        badge.innerHTML = '<span class="psls-pulse-dot" style="width:4px; height:4px; border-radius:50%; background-color:var(--psls-c-success-text); display:inline-block;"></span>已启用';
      } else {
        badge.style.backgroundColor = 'var(--psls-c-gray-18)';
        badge.style.color = 'var(--psls-c-gray-text)';
        badge.innerHTML = '已禁用';
      }
    }

    function updateProtectHero(states) {
      // 按保护页实际展示的开关行（data-module）统计，避免计入无 UI 的遗留键（如 visual-prank）
      var keys = [];
      document.querySelectorAll('[data-module]').forEach(function(el) {
        var k = el.getAttribute('data-module');
        if (k) keys.push(k);
      });
      var enabledCount = keys.filter(function(k) { return states[k]; }).length;
      var total = keys.length;
      var heroTitle = document.getElementById('protect-hero-title');
      var heroBadge = document.getElementById('protect-hero-badge');
      var heroSubtitle = document.getElementById('protect-hero-subtitle');
      var heroIcon = document.getElementById('protect-hero-icon');
      var ring = document.getElementById('protect-ring');
      if (!heroTitle) return;

      if (enabledCount === total) {
        heroTitle.textContent = '防护已开启';
        heroBadge.style.backgroundColor = 'var(--psls-c-success-15)';
        heroBadge.style.color = 'var(--psls-c-success-text)';
        heroBadge.innerHTML = '<span class="psls-pulse-dot" style="width:6px; height:6px; border-radius:50%; background-color:var(--psls-c-success-text); display:inline-block;"></span>运行中';
        heroSubtitle.textContent = '所有防护模块正常运行';
        heroIcon.setAttribute('data-lucide', 'shield-check');
        heroIcon.style.color = 'var(--psls-primary)';
        if (ring) {
          ring.style.background = 'conic-gradient(from var(--psls-ring-angle), var(--psls-c-accent), var(--psls-c-accent-glow), var(--psls-c-accent))';
          ring.classList.add('psls-ring-rotate');
        }
      } else if (enabledCount === 0) {
        heroTitle.textContent = '防护已关闭';
        heroBadge.style.backgroundColor = 'var(--psls-c-danger-15)';
        heroBadge.style.color = 'var(--psls-c-danger-text)';
        heroBadge.innerHTML = '<span style="width:6px; height:6px; border-radius:50%; background-color:var(--psls-c-danger-text); display:inline-block;"></span>已停止';
        heroSubtitle.textContent = '所有防护模块均已禁用';
        heroIcon.setAttribute('data-lucide', 'shield-off');
        heroIcon.style.color = 'var(--psls-danger)';
        if (ring) {
          ring.style.background = 'conic-gradient(from var(--psls-ring-angle), var(--psls-c-danger-dot), var(--psls-c-danger-lite), var(--psls-c-danger-dot))';
          ring.classList.remove('psls-ring-rotate');
        }
      } else {
        heroTitle.textContent = '防护部分开启';
        heroBadge.style.backgroundColor = 'var(--psls-c-warn-15)';
        heroBadge.style.color = 'var(--psls-c-warn-text2)';
        heroBadge.innerHTML = '<span class="psls-pulse-dot" style="width:6px; height:6px; border-radius:50%; background-color:var(--psls-c-warn-dot); display:inline-block;"></span>部分运行';
        heroSubtitle.textContent = enabledCount + '/' + total + ' 个防护模块运行中';
        heroIcon.setAttribute('data-lucide', 'shield-alert');
        heroIcon.style.color = 'var(--psls-warning)';
        if (ring) {
          ring.style.background = 'conic-gradient(from var(--psls-ring-angle), var(--psls-c-warn-dot), var(--psls-c-warn-alt), var(--psls-c-warn-dot))';
          ring.classList.add('psls-ring-rotate');
        }
      }
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    }

    function refreshProtectUI() {
      var states = loadProtectStates();
      var modules = document.querySelectorAll('[data-module]');
      modules.forEach(function(moduleEl) {
        var key = moduleEl.getAttribute('data-module');
        var input = moduleEl.querySelector('input[type="checkbox"]');
        if (!input) return;
        input.checked = !!states[key];
        updateModuleStatus(moduleEl, input.checked);
      });
      updateProtectHero(states);
      refreshDashboardPanel();
    }

    function initProtectModules() {
      var states = loadProtectStates();
      var modules = document.querySelectorAll('[data-module]');
      modules.forEach(function(moduleEl) {
        var key = moduleEl.getAttribute('data-module');
        var input = moduleEl.querySelector('input[type="checkbox"]');
        if (!input) return;
        input.checked = !!states[key];
        applyToggleState(input.closest('.psls-toggle'), input.checked);
        updateModuleStatus(moduleEl, input.checked);
        input.addEventListener('change', function() {
          states[key] = input.checked;
          saveProtectStates(states);
          applyToggleState(input.closest('.psls-toggle'), input.checked);
          updateModuleStatus(moduleEl, input.checked);
          updateProtectHero(states);
          if (pyBridge) pyBridge.toggleModule(key, input.checked);
          refreshDashboardPanel();
        });
      });
      updateProtectHero(states);
    }

    function initAllToggles() {
      var toggles = document.querySelectorAll('.psls-toggle');
      toggles.forEach(function(toggle) {
        var input = toggle.querySelector('input[type="checkbox"]');
        if (!input) return;
        applyToggleState(toggle, input.checked);
        input.addEventListener('change', function() {
          applyToggleState(toggle, input.checked);
        });
      });
    }

    // ===== YARA 引擎状态同步 =====
    function syncYaraStatus() {
      if (!pyBridge) return;
      try {
        var raw = pyBridge.getRuleEngineStatus();
        console.log('[YARA] getRuleEngineStatus raw type=', typeof raw, 'value=', raw);
        // 兼容多种返回类型：QWebChannel 可能返回 JSON 字符串、对象、QVariant 包装
        var status = null;
        if (typeof raw === 'string') {
          try { status = JSON.parse(raw); } catch (e) { status = null; }
        } else if (raw && typeof raw === 'object') {
          status = raw;
        } else if (raw !== undefined && raw !== null && typeof raw.toString === 'function') {
          // 某些情况下返回的是带 toString 的 QVariant 包装
          try { status = JSON.parse(String(raw)); } catch (e) { status = null; }
        }
        if (!status || typeof status !== 'object') {
          console.warn('YARA 状态返回异常:', raw);
          return;
        }
        console.log('[YARA] 状态同步:', status);
        // 兼容不同字段名：yara_installed / yara_available / yara_direct / yara_portable
        var yaraEnabled = !!status.yara_enabled;
        var yaraInstalled = !!(
          status.yara_installed ||
          status.yara_available ||
          status.yara_direct ||
          status.yara_portable
        );
        var yaraAvailable = !!status.yara_available;

        // 更新主页指示灯和一键安装按钮（使用统一颜色）
        var installBtn = document.getElementById('btn-install-yara');
        if (yaraEnabled && yaraInstalled) {
          dashSetItem('yara', 'YARA 引擎', 'green', '已启用');
        } else if (yaraInstalled && !yaraEnabled) {
          dashSetItem('yara', 'YARA 引擎', 'yellow', '已禁用');
        } else {
          dashSetItem('yara', 'YARA 引擎', 'gray', '未检测');
        }
        if (installBtn) {
          if (yaraInstalled) {
            installBtn.classList.add('hidden');
          } else {
            installBtn.classList.remove('hidden');
            if (window.lucide) lucide.createIcons();
          }
        }

        // 更新设置页开关和标签
        var yaraToggle = document.getElementById('set-yara');
        var yaraLabel = document.getElementById('set-yara-status-label');
        if (yaraToggle) {
          yaraToggle.checked = yaraEnabled;
          applyToggleState(yaraToggle.closest('.psls-toggle'), yaraEnabled);
          // 未安装时禁用开关
          if (!yaraInstalled) {
            yaraToggle.disabled = true;
            yaraToggle.closest('.psls-toggle').style.opacity = '0.4';
            yaraToggle.closest('.psls-toggle').style.pointerEvents = 'none';
          }
        }
        if (yaraLabel) {
          if (yaraInstalled && yaraEnabled) {
            yaraLabel.style.color = 'var(--psls-c-success-text)';
            yaraLabel.textContent = '已启用';
          } else if (yaraInstalled && !yaraEnabled) {
            yaraLabel.style.color = 'var(--psls-c-warn-text)';
            yaraLabel.textContent = '已禁用';
          } else {
            yaraLabel.style.color = 'var(--psls-c-danger-text)';
            yaraLabel.textContent = '未安装';
          }
        }
      } catch(e) {
        console.warn('同步 YARA 状态失败:', e);
      }
    }

    // 一键安装 YARA 引擎
    function installYara() {
      if (!pyBridge || !pyBridge.installYara) {
        showInfoToast('YARA 安装', '桥接对象未就绪，请稍后重试', 'warning', 4000);
        return;
      }
      var btn = document.getElementById('btn-install-yara');
      if (btn) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'not-allowed';
      }
      showInfoToast('YARA 安装', '开始安装 yara-python，请稍候...', 'info', 6000);
      try {
        pyBridge.installYara();
      } catch(e) {
        showInfoToast('YARA 安装', '调用安装失败: ' + e.message, 'danger', 5000);
        if (btn) {
          btn.disabled = false;
          btn.style.opacity = '1';
          btn.style.cursor = 'pointer';
        }
      }
    }

    // 处理 YARA 安装结果
    function onYaraInstallResult(result) {
      if (!result) return;
      var status = result.status || 'info';
      var message = result.message || '';
      var btn = document.getElementById('btn-install-yara');

      // 检查和下载状态：保持按钮禁用，显示进度
      if (status === 'checking' || status === 'downloading') {
        if (btn) {
          btn.disabled = true;
          btn.style.opacity = '0.6';
          btn.style.cursor = 'not-allowed';
        }
        showInfoToast('YARA 安装', message, 'info', 4000, true);
        return;
      }

      if (status === 'installing') {
        showInfoToast('YARA 安装', message, 'info', 4000, true);
        return;
      }
      if (btn) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
      }
      if (status === 'success') {
        showInfoToast('YARA 安装成功', message, 'success', 5000, true);
      } else if (status === 'warning') {
        showInfoToast('YARA 安装提示', message, 'warning', 6000, true);
      } else {
        showInfoToast('YARA 安装失败', message, 'danger', 8000, true);
      }
      // 刷新状态显示：依赖 Python 信号推送（ruleEngineStatusChanged），不再轮询
      // 信号推送有防御性检查和状态兜底，比轮询更可靠
    }

    // 一键安装 ML 引擎
    function installMl() {
      if (!pyBridge || !pyBridge.installMl) {
        showInfoToast('ML 安装', '桥接对象未就绪，请稍后重试', 'warning', 4000);
        return;
      }
      var btn = document.getElementById('btn-install-ml');
      if (btn) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'not-allowed';
      }
      showInfoToast('ML 安装', '开始安装 ML 检测引擎，请稍候...', 'info', 6000);
      try {
        pyBridge.installMl();
      } catch(e) {
        showInfoToast('ML 安装', '调用安装失败: ' + e.message, 'danger', 5000);
        if (btn) {
          btn.disabled = false;
          btn.style.opacity = '1';
          btn.style.cursor = 'pointer';
        }
      }
    }

    // 处理 ML 安装结果
    function onMlInstallResult(result) {
      if (!result) return;
      var status = result.status || 'info';
      var message = result.message || '';
      var btn = document.getElementById('btn-install-ml');

      // 检查和下载状态：保持按钮禁用，显示进度
      if (status === 'checking' || status === 'downloading' || status === 'installing') {
        if (btn) {
          btn.disabled = true;
          btn.style.opacity = '0.6';
          btn.style.cursor = 'not-allowed';
        }
        showInfoToast('ML 安装', message, 'info', 4000, true);
        return;
      }

      if (btn) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
      }
      if (status === 'success') {
        showInfoToast('ML 安装成功', message, 'success', 5000, true);
      } else if (status === 'warning') {
        showInfoToast('ML 安装提示', message, 'warning', 6000, true);
      } else {
        showInfoToast('ML 安装失败', message, 'danger', 8000, true);
      }
      // 状态刷新依赖 Python 信号推送（mlEngineStatusChanged）
    }

    // 导入训练数据并重新训练
    function selectMlTrainData() {
      if (!pyBridge || !pyBridge.selectMlTrainData) {
        showInfoToast('ML 训练', '桥接对象未就绪，请稍后重试', 'warning', 4000);
        return;
      }
      var btn = document.getElementById('btn-ml-train-import');
      if (btn) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'not-allowed';
      }
      showInfoToast('ML 训练', '请选择 JSON 训练数据文件...', 'info', 4000);
      try {
        pyBridge.selectMlTrainData();
      } catch(e) {
        showInfoToast('ML 训练', '调用失败: ' + e.message, 'danger', 5000);
        if (btn) {
          btn.disabled = false;
          btn.style.opacity = '1';
          btn.style.cursor = 'pointer';
        }
      }
    }

    // 导出训练数据
    function exportMlTrainData() {
      if (!pyBridge || !pyBridge.exportMlTrainData) {
        showInfoToast('ML 导出', '桥接对象未就绪，请稍后重试', 'warning', 4000);
        return;
      }
      var btn = document.getElementById('btn-ml-train-export');
      if (btn) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'not-allowed';
      }
      try {
        pyBridge.exportMlTrainData();
      } catch(e) {
        showInfoToast('ML 导出', '调用失败: ' + e.message, 'danger', 5000);
        if (btn) {
          btn.disabled = false;
          btn.style.opacity = '1';
          btn.style.cursor = 'pointer';
        }
      }
    }

    // 处理 ML 训练/导出结果
    function onMlTrainResult(result) {
      if (!result) return;
      var status = result.status || 'info';
      var message = result.message || '';
      var importBtn = document.getElementById('btn-ml-train-import');
      var exportBtn = document.getElementById('btn-ml-train-export');

      // training / exporting：保持按钮禁用，ML 指示灯变黄色
      if (status === 'training' || status === 'exporting') {
        if (importBtn) {
          importBtn.disabled = true;
          importBtn.style.opacity = '0.6';
          importBtn.style.cursor = 'not-allowed';
        }
        if (exportBtn) {
          exportBtn.disabled = true;
          exportBtn.style.opacity = '0.6';
          exportBtn.style.cursor = 'not-allowed';
        }
        // 主页指示灯：黄色"训练中"
        dashSetItem('ml', 'ML 引擎', 'yellow', '训练中');
        // 设置页标签同步
        var setMlLabel = document.getElementById('set-ml-status-label');
        if (setMlLabel) {
          setMlLabel.style.color = 'var(--psls-c-warn-text)';
          setMlLabel.textContent = '训练中';
        }
        showInfoToast('ML 训练', message, 'info', 6000, true);
        return;
      }

      // 恢复按钮
      if (importBtn) {
        importBtn.disabled = false;
        importBtn.style.opacity = '1';
        importBtn.style.cursor = 'pointer';
      }
      if (exportBtn) {
        exportBtn.disabled = false;
        exportBtn.style.opacity = '1';
        exportBtn.style.cursor = 'pointer';
      }

      // 训练未改变模型时（cancelled/error），恢复指示灯到实际状态
      if (status === 'cancelled' || status === 'error') {
        if (pyBridge && pyBridge.getMlEngineStatus) {
          try {
            var r = pyBridge.getMlEngineStatus();
            if (r && typeof r.then === 'function') {
              r.then(function(s) { if (s) applyMlStatus(s); });
            } else if (r) {
              applyMlStatus(r);
            }
          } catch(e) {}
        }
      }

      if (status === 'cancelled') {
        return;  // 用户取消，不弹提示
      }
      if (status === 'export_success') {
        showInfoToast('ML 导出成功', message, 'success', 6000, true);
      } else if (status === 'success') {
        showInfoToast('ML 训练完成', message, 'success', 6000, true);
      } else if (status === 'warning') {
        showInfoToast('ML 训练提示', message, 'warning', 6000, true);
      } else {
        showInfoToast('ML 操作失败', message, 'danger', 8000, true);
      }
    }

    // 显示训练数据格式说明弹窗
    function showMlTrainHelp() {
      var html = ''
        + '<div style="text-align:left; font-size:13px; line-height:1.7; color:var(--psls-card-foreground);">'
        + '<p style="margin:0 0 8px;"><b>当前 ML 检测由两级引擎组成：</b></p>'
        + '<p style="margin:0 0 4px;">• <b>主引擎</b>：SOREL-20M / EMBER v2（<b>2381 维</b>特征）LightGBM，全局优先级最高，模型随程序内置，<b>不通过此弹窗导入</b>。</p>'
        + '<p style="margin:0 0 10px;">• <b>回退引擎</b>：轻量神经网络 MLP（<b>128 维</b>特征），仅当主引擎未给出判定时使用。<b>本弹窗的「导入并训练 / 导出」针对的就是该回退模型。</b></p>'
        + '<p style="margin:0 0 8px;"><b>支持 JSON 格式，两种写法均可：</b></p>'
        + '<p style="margin:0 0 4px; color:var(--psls-primary);"><b>格式 1：带标签列表（推荐）</b></p>'
        + '<pre style="background:var(--psls-muted); padding:8px 10px; border-radius:4px; font-size:11px; overflow-x:auto; margin:4px 0 10px;">'
        + '{\n'
        + '  "samples": [\n'
        + '    {"features": [128个浮点数], "label": "clean"},\n'
        + '    {"features": [128个浮点数], "label": "malware"}\n'
        + '  ]\n'
        + '}'
        + '</pre>'
        + '<p style="margin:0 0 4px; color:var(--psls-primary);"><b>格式 2：分组列表</b></p>'
        + '<pre style="background:var(--psls-muted); padding:8px 10px; border-radius:4px; font-size:11px; overflow-x:auto; margin:4px 0 10px;">'
        + '{\n'
        + '  "clean": [[128个浮点数], ...],\n'
        + '  "malware": [[128个浮点数], ...]\n'
        + '}'
        + '</pre>'
        + '<p style="margin:0 0 4px;">格式 2 的 key 也支持 <code>benign</code>/<code>safe</code>（等同 clean）和 <code>malicious</code>/<code>threat</code>（等同 malware）。</p>'
        + '<p style="margin:10px 0 4px;"><b>128 维特征向量说明（回退 MLP 模型）</b></p>'
        + '<table style="width:100%; font-size:11px; border-collapse:collapse;">'
        + '<tr style="background:var(--psls-muted);"><th style="padding:4px 6px; text-align:left;">索引</th><th style="padding:4px 6px; text-align:left;">特征</th><th style="padding:4px 6px; text-align:left;">说明</th></tr>'
        + '<tr><td style="padding:3px 6px;">0-63</td><td style="padding:3px 6px;">字节直方图</td><td style="padding:3px 6px;">256 bin 每 4 个合并为 1 bin，归一化</td></tr>'
        + '<tr><td style="padding:3px 6px;">64</td><td style="padding:3px 6px;">全局熵值</td><td style="padding:3px 6px;">entropy / 8.0</td></tr>'
        + '<tr><td style="padding:3px 6px;">65</td><td style="padding:3px 6px;">文件大小</td><td style="padding:3px 6px;">log(size+1) / 20.0</td></tr>'
        + '<tr><td style="padding:3px 6px;">66-73</td><td style="padding:3px 6px;">PE 结构特征</td><td style="padding:3px 6px;">是否PE/节区数/是否DLL/32位/64位等</td></tr>'
        + '<tr><td style="padding:3px 6px;">74-81</td><td style="padding:3px 6px;">可疑 API</td><td style="padding:3px 6px;">按 8 功能类别计数，归一化</td></tr>'
        + '<tr><td style="padding:3px 6px;">82-89</td><td style="padding:3px 6px;">可疑关键词</td><td style="padding:3px 6px;">按 8 类别计数，归一化</td></tr>'
        + '<tr><td style="padding:3px 6px;">90-105</td><td style="padding:3px 6px;">DLL 名称哈希</td><td style="padding:3px 6px;">16 维，EMBER 风格</td></tr>'
        + '<tr><td style="padding:3px 6px;">106-111</td><td style="padding:3px 6px;">节区统计</td><td style="padding:3px 6px;">6 维节区特征</td></tr>'
        + '<tr><td style="padding:3px 6px;">112-119</td><td style="padding:3px 6px;">Top-8 Bigram</td><td style="padding:3px 6px;">最高频 8 个双字节序列频率</td></tr>'
        + '<tr><td style="padding:3px 6px;">120-122</td><td style="padding:3px 6px;">文件类型</td><td style="padding:3px 6px;">EXE/DLL/SYS 标记</td></tr>'
        + '<tr><td style="padding:3px 6px;">123-127</td><td style="padding:3px 6px;">字符串统计</td><td style="padding:3px 6px;">可打印/零字节/高熵字节/控制字符/保留</td></tr>'
        + '</table>'
        + '<p style="margin:10px 0 0; color:var(--psls-muted-foreground); font-size:11px;">导入后自动合并系统采集数据训练 128 维回退模型；2381 维主引擎（EMBER v2 LightGBM）不受影响。</p>'
        + '</div>';
      showFloatWindow('训练数据格式说明', html, '<button class="psls-btn psls-btn-primary" onclick="this.closest(\'.float-window\').parentNode.removeChild(this.closest(\'.float-window\'))">知道了</button>', 560);
    }

    function showSigImportHelp() {
      var html = ''
        + '<div style="text-align:left; font-size:13px; line-height:1.7; color:var(--psls-card-foreground);">'
        + '<p style="margin:0 0 8px;"><b>支持以下导入格式：</b></p>'
        // JSON
        + '<p style="margin:0 0 4px; color:var(--psls-primary);"><b>1. JSON 文件（.json）</b></p>'
        + '<p style="margin:0 0 4px;">支持完整签名库导出格式和纯哈希列表：</p>'
        + '<p style="margin:4px 0 2px; font-size:12px; color:var(--psls-muted-foreground);">完整格式（含元数据）：</p>'
        + '<pre style="background:var(--psls-muted); padding:8px 10px; border-radius:4px; font-size:11px; overflow-x:auto; margin:4px 0 8px;">'
        + '{\n'
        + '  "malwares": [\n'
        + '    {"hash_sha256": "64位SHA256",\n'
        + '     "name": "Trojan.XXX",\n'
        + '     "type": "Trojan",\n'
        + '     "severity": "high",\n'
        + '     "description": "..."}\n'
        + '  ],\n'
        + '  "heuristics": [...],\n'
        + '  "whitelist": [...]\n'
        + '}'
        + '</pre>'
        + '<p style="margin:4px 0 2px; font-size:12px; color:var(--psls-muted-foreground);">纯哈希列表（自动命名为 Imported-xxxxxxxx）：</p>'
        + '<pre style="background:var(--psls-muted); padding:8px 10px; border-radius:4px; font-size:11px; overflow-x:auto; margin:4px 0 8px;">'
        + '["hash1", "hash2", "hash3", ...]'
        + '</pre>'
        + '<p style="margin:4px 0 2px; font-size:12px; color:var(--psls-muted-foreground);">或带 hash_sha256 字段的对象数组：</p>'
        + '<pre style="background:var(--psls-muted); padding:8px 10px; border-radius:4px; font-size:11px; overflow-x:auto; margin:4px 0 10px;">'
        + '[{"hash_sha256": "xxx", "name": "Test"}]'
        + '</pre>'
        // TXT
        + '<p style="margin:0 0 4px; color:var(--psls-primary);"><b>2. 文本文件（.txt）</b></p>'
        + '<p style="margin:0 0 4px;">每行一条记录，支持以下写法：</p>'
        + '<pre style="background:var(--psls-muted); padding:8px 10px; border-radius:4px; font-size:11px; overflow-x:auto; margin:4px 0 8px;">'
        + '# 纯哈希（每行一个64位SHA256）\n'
        + 'a1b2c3d4e5f6...（64位）\n'
        + '\n'
        + '# 带名称和类型（逗号分隔）\n'
        + 'a1b2c3d4...,Trojan.XXX,Trojan,high\n'
        + '\n'
        + '# 以 # 开头的行为注释，会被跳过'
        + '</pre>'
        // DB
        + '<p style="margin:0 0 4px; color:var(--psls-primary);"><b>3. SQLite 数据库（.db）</b></p>'
        + '<p style="margin:0 0 4px;">导入其他 PSLS 导出的 .db 签名库文件，自动合并所有签名、启发式规则和白名单。</p>'
        // 字段说明
        + '<p style="margin:10px 0 4px;"><b>字段说明</b></p>'
        + '<table style="width:100%; font-size:11px; border-collapse:collapse;">'
        + '<tr style="background:var(--psls-muted);"><th style="padding:4px 6px; text-align:left;">字段</th><th style="padding:4px 6px; text-align:left;">说明</th><th style="padding:4px 6px; text-align:left;">默认值</th></tr>'
        + '<tr><td style="padding:3px 6px;">hash_sha256</td><td style="padding:3px 6px;">64 位 SHA256 哈希（必填）</td><td style="padding:3px 6px;">—</td></tr>'
        + '<tr><td style="padding:3px 6px;">name</td><td style="padding:3px 6px;">签名名称</td><td style="padding:3px 6px;">Imported-xxxxxxxx</td></tr>'
        + '<tr><td style="padding:3px 6px;">type</td><td style="padding:3px 6px;">类型（Trojan/Spyware/Ransomware...）</td><td style="padding:3px 6px;">import</td></tr>'
        + '<tr><td style="padding:3px 6px;">severity</td><td style="padding:3px 6px;">严重度（critical/high/medium/low）</td><td style="padding:3px 6px;">high</td></tr>'
        + '<tr><td style="padding:3px 6px;">description</td><td style="padding:3px 6px;">描述信息</td><td style="padding:3px 6px;">空</td></tr>'
        + '</table>'
        + '<p style="margin:10px 0 0; color:var(--psls-muted-foreground); font-size:11px;">导入时自动去重，已存在的哈希不会重复添加。</p>'
        + '</div>';
      showFloatWindow('签名库导入格式说明', html, '<button class="psls-btn psls-btn-primary" onclick="this.closest(\'.float-window\').parentNode.removeChild(this.closest(\'.float-window\'))">知道了</button>', 560);
    }

    function applyToggleState(toggle, checked) {
      if (checked) {
        toggle.classList.add('is-on');
      } else {
        toggle.classList.remove('is-on');
      }
    }

    // ===== Modal helpers =====
    function showModal(title, bodyHtml, footerHtml) {
      var container = document.getElementById('modal-container');
      if (!container) return;
      var overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      overlay.innerHTML =
        '<div class="modal-card">' +
          '<div class="modal-header">' +
            '<span style="font-size:15px; font-weight:600; color:var(--psls-foreground);">' + escapeHtml(title) + '</span>' +
            '<button class="modal-close" style="background:transparent; border:none; cursor:pointer; color:var(--psls-muted-foreground); font-size:18px; padding:4px 8px;">&times;</button>' +
          '</div>' +
          '<div class="modal-body">' + bodyHtml + '</div>' +
          (footerHtml ? '<div class="modal-footer">' + footerHtml + '</div>' : '') +
        '</div>';
      container.appendChild(overlay);
      var closeBtn = overlay.querySelector('.modal-close');
      if (closeBtn) closeBtn.addEventListener('click', function() { closeModal(overlay); });
      overlay.addEventListener('click', function(e) { if (e.target === overlay) closeModal(overlay); });
      if (window.lucide) lucide.createIcons();
      return overlay;
    }

    function closeModal(overlay) {
      if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
    }

    // 浮动独立窗口（可拖动、不遮挡页面操作）
    function showFloatWindow(title, bodyHtml, footerHtml, width, height) {
      var container = document.getElementById('modal-container') || document.body;
      var win = document.createElement('div');
      win.className = 'float-window';
      win.style.width = (width || 520) + 'px';
      win.style.maxWidth = '90vw';
      win.style.maxHeight = '80vh';
      // 居中偏上
      win.style.left = '50%';
      win.style.top = '12%';
      win.style.transform = 'translateX(-50%)';

      win.innerHTML =
        '<div class="float-window-header">' +
          '<span style="font-size:14px; font-weight:600; color:var(--psls-foreground);">' + escapeHtml(title) + '</span>' +
          '<button class="modal-close" style="background:transparent; border:none; cursor:pointer; color:var(--psls-muted-foreground); font-size:18px; padding:2px 8px; line-height:1;">&times;</button>' +
        '</div>' +
        '<div class="float-window-body">' + bodyHtml + '</div>' +
        (footerHtml ? '<div class="float-window-footer">' + footerHtml + '</div>' : '');

      container.appendChild(win);

      // 关闭按钮
      var closeBtn = win.querySelector('.modal-close');
      if (closeBtn) closeBtn.addEventListener('click', function() { win.parentNode.removeChild(win); });

      // 拖动逻辑
      var header = win.querySelector('.float-window-header');
      var isDragging = false, offX = 0, offY = 0;
      header.addEventListener('mousedown', function(e) {
        if (e.target.tagName === 'BUTTON') return;
        isDragging = true;
        var rect = win.getBoundingClientRect();
        offX = e.clientX - rect.left;
        offY = e.clientY - rect.top;
        win.style.transform = 'none';
        header.style.cursor = 'grabbing';
        e.preventDefault();
      });
      document.addEventListener('mousemove', function(e) {
        if (!isDragging) return;
        var x = e.clientX - offX;
        var y = e.clientY - offY;
        // 限制不超出视口
        x = Math.max(0, Math.min(x, window.innerWidth - win.offsetWidth));
        y = Math.max(0, Math.min(y, window.innerHeight - 40));
        win.style.left = x + 'px';
        win.style.top = y + 'px';
      });
      document.addEventListener('mouseup', function() {
        if (isDragging) {
          isDragging = false;
          header.style.cursor = 'move';
        }
      });

      if (window.lucide) lucide.createIcons();
      return win;
    }

    // 通用信息提示（复用 threat-toast 样式，无交互按钮）
    // 可缩放 toast 的全局尺寸比例（百分比），持久化到 localStorage
    var _toastScale = parseInt(localStorage.getItem('psls_toast_scale') || '100', 10);
    if (isNaN(_toastScale) || _toastScale < 50) _toastScale = 100;
    if (_toastScale > 300) _toastScale = 300;

    // 对 toast 元素应用全局缩放（同时缩放窗口大小与文字大小）
    function _applyToastScale(toast) {
      var s = _toastScale / 100;
      if (s !== 1) {
        toast.style.zoom = s;
      }
    }

    function showInfoToast(title, message, type, duration, resizable) {
      var container = document.getElementById('threat-toast-container');
      if (!container) return;
      type = type || 'info';
      duration = duration || 5000;
      var headerClass = type;
      var icon = type === 'success' ? '✓' : type === 'warning' ? '⚠' : type === 'danger' ? '✗' : 'ℹ';
      var toastId = 'toast-' + (++_toastSeq);
      var toast = document.createElement('div');
      toast.className = 'threat-toast';
      toast.id = toastId;
      toast.style.position = 'relative';

      // 应用全局缩放（对窗口大小与文字大小均生效）
      _applyToastScale(toast);

      toast.innerHTML =
        '<div class="threat-toast-header ' + headerClass + '">' +
          '<span style="font-size:16px;">' + icon + '</span>' +
          '<span>' + escapeHtml(title) + '</span>' +
        '</div>' +
        '<div class="threat-toast-body">' +
          '<div style="font-weight:500;">' + escapeHtml(message) + '</div>' +
        '</div>';

      container.appendChild(toast);

      setTimeout(function() { removeToast(toastId); }, duration);
    }

    // 设置页：弹窗大小滑块实时更新（同时同步屏幕弹窗缩放）
    function updateToastScaleFromSlider(el) {
      var v = parseInt(el.value, 10) || 100;
      if (isNaN(v) || v < 50) v = 50;
      if (v > 300) v = 300;
      _toastScale = v;
      localStorage.setItem('psls_toast_scale', String(v));
      var label = document.getElementById('cfg-toast-scale-label');
      if (label) label.textContent = v + '%';
      // 同步屏幕弹窗（桌面右下角 QWidget）的缩放比例
      if (window.bridge && bridge.setPopupScale) {
        try { bridge.setPopupScale(v); } catch (e) { /* 忽略 */ }
      }
    }

    // 设置页：测试弹窗大小（在屏幕右下角弹出，缩放对窗口大小与文字大小均生效）
    function testToastSize() {
      var container = document.getElementById('threat-toast-container');
      if (!container) return;
      var toastId = 'toast-' + (++_toastSeq);
      var toast = document.createElement('div');
      toast.className = 'threat-toast';
      toast.id = toastId;
      toast.style.position = 'relative';
      _applyToastScale(toast);
      toast.innerHTML =
        '<div class="threat-toast-header danger">' +
          '<span>弹窗大小测试</span>' +
        '</div>' +
        '<div class="threat-toast-body">' +
          '<div>当前比例：' + _toastScale + '%</div>' +
          '<div class="file-path">C:\\Windows\\System32\\test_sample.exe</div>' +
        '</div>' +
        '<div class="threat-toast-actions" style="flex-direction:column;">' +
          '<button class="threat-toast-btn threat-toast-btn-auto">自动处理</button>' +
          '<div style="display:flex; gap:8px;">' +
            '<button class="threat-toast-btn threat-toast-btn-secondary">忽略</button>' +
            '<button class="threat-toast-btn threat-toast-btn-trust">忽略并信任</button>' +
          '</div>' +
        '</div>';
      container.appendChild(toast);
      // 绑定按钮用于关闭
      toast.querySelectorAll('button').forEach(function(btn) {
        btn.addEventListener('click', function() { removeToast(toastId); });
      });
      setTimeout(function() { removeToast(toastId); }, 5000);
    }

    // 初始化设置页弹窗大小滑块（与 localStorage 同步）
    function initToastScaleControl() {
      var slider = document.getElementById('cfg-toast-scale');
      var label = document.getElementById('cfg-toast-scale-label');
      var v = parseInt(localStorage.getItem('psls_toast_scale') || '100', 10);
      if (isNaN(v) || v < 50 || v > 300) v = 100;
      _toastScale = v;
      if (slider) slider.value = String(v);
      if (label) label.textContent = v + '%';
      // 用保存的初始值同步一次屏幕弹窗缩放比例
      if (window.bridge && bridge.setPopupScale) {
        try { bridge.setPopupScale(v); } catch (e) { /* 忽略 */ }
      }
    }

    // ===== Utility =====
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    // 格式化文件大小（字节 → KB/MB/GB）
    function formatFileSize(bytes) {
      if (bytes === null || bytes === undefined || isNaN(bytes)) return '—';
      var b = Number(bytes);
      if (b < 1024) return b + ' B';
      if (b < 1024 * 1024) return (b / 1024).toFixed(2) + ' KB';
      if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(2) + ' MB';
      return (b / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }

    // ===== 工具子页面：通用文件选择处理 =====
    function handleFileSelected(path, target) {
      if (!path) return;
      if (target === 'signature' || target === 'virus') {
        var sigInput = document.getElementById('sig-path-input');
        if (sigInput) sigInput.value = path;
        appendSigLog('已选择文件: ' + path, 'info');
      } else if (target === 'pe') {
        var peInput = document.getElementById('pe-file-path');
        if (peInput) peInput.value = path;
        // 选择后自动开始分析
        if (pyBridge) pyBridge.analyzePEFile(path);
      } else if (target === 'sandbox') {
        var sbInput = document.getElementById('sandbox-file-path');
        if (sbInput) sbInput.value = path;
        var startBtn = document.getElementById('sandbox-start-btn');
        if (startBtn) startBtn.style.display = 'flex';
      } else if (target === 'hash') {
        var hashInput = document.getElementById('hash-file-path');
        if (hashInput) hashInput.value = path;
        // 选择后自动计算哈希
        if (pyBridge) pyBridge.calculateFileHash(path);
      }
    }

    // ========================================================================
    // ===== 子页面：勒索文件回滚中心 =====
    // ========================================================================
    function loadRollbackRecords() {
      if (!pyBridge) return;
      try {
        var raw = pyBridge.getRollbackRecords();
        var obj = (typeof raw === 'string') ? JSON.parse(raw) : raw;
        if (obj) renderRollbackRecords(obj);
      } catch(e) { console.error('getRollbackRecords error:', e); }
    }

    function renderRollbackRecords(data) {
      var listEl = document.getElementById('rollback-list');
      var emptyEl = document.getElementById('rollback-empty-state');
      var summaryEl = document.getElementById('rollback-stats-summary');
      if (!listEl) return;
      listEl.querySelectorAll('.rbrow').forEach(function(r) { r.remove(); });
      var records = (data && data.records) || [];
      if (emptyEl) emptyEl.style.display = records.length ? 'none' : 'flex';
      if (summaryEl) summaryEl.textContent = '共 ' + records.length + ' 条记录';
      var badge = document.getElementById('rollback-badge');
      if (badge) badge.textContent = records.length + ' 条记录';

      records.forEach(function(rec) {
        var row = document.createElement('div');
        row.className = 'rbrow';
        row.style.cssText = 'padding:12px 14px; border-bottom:1px solid var(--psls-border-soft);';
        var head = document.createElement('div');
        head.style.cssText = 'display:flex; align-items:center; gap:10px; margin-bottom:6px; flex-wrap:wrap;';
        head.innerHTML =
          '<span style="font-size:13px; font-weight:600; color:var(--psls-foreground);">' + escapeHtml(rec.reason || '') + '</span>' +
          '<span style="font-size:12px; color:var(--psls-muted-foreground);">' + escapeHtml(rec.ts || '') + '</span>' +
          '<span style="font-size:12px; color:var(--psls-success);">恢复 ' + (rec.restored || 0) + '</span>' +
          '<span style="font-size:12px; color:var(--psls-danger);">失败 ' + (rec.failed || 0) + '</span>' +
          '<span style="font-size:12px; color:var(--psls-muted-foreground);">跳过 ' + (rec.skipped || 0) + '</span>';
        row.appendChild(head);
        (rec.files || []).forEach(function(f) {
          var fr = document.createElement('div');
          fr.style.cssText = 'display:flex; align-items:center; gap:8px; padding:2px 0;';
          var color = f.status === 'restored' ? 'var(--psls-success)'
                    : (f.status === 'failed' ? 'var(--psls-danger)' : 'var(--psls-muted-foreground)');
          fr.innerHTML =
            '<span style="font-size:12px; color:' + color + '; width:74px; flex-shrink:0;">' + escapeHtml(f.status || '') + '</span>' +
            '<span title="' + escapeHtml(f.path || '') + '" style="font-size:12px; color:var(--psls-foreground); flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:var(--psls-font-mono);">' + escapeHtml(f.path || '') + '</span>';
          var btn = document.createElement('button');
          btn.textContent = '恢复';
          btn.style.cssText = 'font-size:12px; padding:3px 10px; border:1px solid var(--psls-border); border-radius:6px; background:var(--psls-card); color:var(--psls-primary); cursor:pointer; flex-shrink:0;';
          btn.addEventListener('click', function() {
            if (pyBridge && pyBridge.restoreRollbackFile) {
              pyBridge.restoreRollbackFile(rec.id || 0, f.path || '');
            }
          });
          var delBtn = document.createElement('button');
          delBtn.textContent = '清除备份';
          delBtn.style.cssText = 'font-size:12px; padding:3px 10px; border:1px solid var(--psls-border); border-radius:6px; background:var(--psls-card); color:var(--psls-danger); cursor:pointer; flex-shrink:0;';
          delBtn.addEventListener('click', function() {
            if (pyBridge && pyBridge.deleteRollbackBackup) {
              pyBridge.deleteRollbackBackup(f.hash || f.path || '');
            }
          });
          fr.appendChild(btn);
          fr.appendChild(delBtn);
          row.appendChild(fr);
        });
        listEl.appendChild(row);
      });
      if (window.lucide) lucide.createIcons();
    }

    function handleRollbackCompleted(obj) {
      var action = obj && obj.action;
      if (action === 'state_refresh') {
        // 后端后台刷新完成 → 静默重渲染世代/记录/范围（无 toast）
        try {
          if (obj.generations !== undefined) renderRollbackGenerations(obj.generations);
          if (obj.records !== undefined) renderRollbackRecords(obj);
          if (obj.dirs) {
            var dirsEl = document.getElementById('rollback-dirs-summary');
            if (dirsEl) dirsEl.textContent = '保护 ' + obj.dirs.length + ' 个目录';
          }
        } catch (e) {}
        return;
      }
      if (action === 'snapshot') {
        showInfoToast('勒索文件回滚', '快照完成：新增 ' + (obj.added || 0), 'success', 2000);
      } else if (action === 'restore_single') {
        showInfoToast('勒索文件回滚', obj.ok ? '单文件恢复成功' : '单文件恢复失败',
                      obj.ok ? 'success' : 'warning', 2500);
      } else if (action === 'delete_backup') {
        showInfoToast('勒索文件回滚', obj.ok ? '备份已清除' : '清除备份失败',
                      obj.ok ? 'success' : 'warning', 2500);
      } else {
        var msg = '回滚完成：恢复 ' + (obj.restored || 0) + ' / 失败 ' +
                  (obj.failed || 0) + ' / 跳过 ' + (obj.skipped || 0);
        showInfoToast('勒索文件回滚', msg, (obj.failed ? 'warning' : 'success'), 3000);
      }
      var page = document.getElementById('page-tool-rollback');
      if (page && page.style.display !== 'none') {
        loadRollbackRecords();
        loadRollbackGenerations();
      }
    }

    // ---- 保留世代列表（选择回滚目标）----
    function loadRollbackGenerations() {
      if (!pyBridge || !pyBridge.getRollbackGenerations) return;
      try {
        var raw = pyBridge.getRollbackGenerations();
        var obj = (typeof raw === 'string') ? JSON.parse(raw) : raw;
        renderRollbackGenerations(obj && obj.generations);
      } catch (e) {}
    }

    function renderRollbackGenerations(gens) {
      var listEl = document.getElementById('rollback-generations');
      if (!listEl) return;
      var emptyEl = document.getElementById('rollback-generations-empty');
      var countEl = document.getElementById('rollback-generations-count');
      gens = gens || [];
      // 清除既有世代项（保留空状态节点）
      listEl.querySelectorAll('[data-action="rollback-gen"]').forEach(function (r) { r.remove(); });
      if (countEl) countEl.textContent = gens.length + ' / 3';
      if (emptyEl) emptyEl.style.display = gens.length ? 'none' : '';
      gens.forEach(function (g, i) {
        var row = document.createElement('div');
        row.setAttribute('data-action', 'rollback-gen');
        row.setAttribute('data-generation-id', String(g.generation_id));
        row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;' +
          'padding:6px 10px;border:1px solid var(--psls-border);border-radius:6px;cursor:pointer;' +
          'background-color:var(--psls-background-soft);';
        var left = document.createElement('span');
        left.style.cssText = 'font-size:12.5px;color:var(--psls-foreground);';
        left.textContent = (g.created_at_str || ('世代 ' + g.generation_id)) +
          '  ·  ' + (g.file_count || 0) + ' 个文件' + (i === 0 ? '  (最新)' : '');
        var right = document.createElement('span');
        right.style.cssText = 'font-size:11.5px;color:var(--psls-muted-foreground);';
        right.textContent = '回滚到此世代';
        row.appendChild(left);
        row.appendChild(right);
        row.addEventListener('click', function () {
          var ok = window.confirm(
            '确定回滚到该世代吗？\n\n' + left.textContent +
            '\n将基于该世代快照恢复受保护目录中的文件（按原路径写回原内容）。'
          );
          if (!ok) return;
          if (pyBridge && pyBridge.triggerRollbackGeneration) {
            pyBridge.triggerRollbackGeneration(g.generation_id);
            var st = document.getElementById('rollback-status-text');
            if (st) st.textContent = '回滚中...';
          }
        });
        listEl.appendChild(row);
      });
      if (window.lucide) lucide.createIcons();
    }

    var _rollbackPageInitialized = false;
    function initRollbackPage() {
      if (_rollbackPageInitialized) return;
      var page = document.getElementById('page-tool-rollback');
      if (!page) return;
      _rollbackPageInitialized = true;
      var snapBtn = page.querySelector('[data-action="rollback-snapshot"]');
      if (snapBtn) snapBtn.addEventListener('click', function() {
        if (pyBridge && pyBridge.rollbackSnapshotNow) {
          pyBridge.rollbackSnapshotNow();
          var st = document.getElementById('rollback-status-text');
          if (st) st.textContent = '快照中...';
        }
      });
      var refreshBtn = page.querySelector('[data-action="rollback-refresh"]');
      if (refreshBtn) refreshBtn.addEventListener('click', function() {
        loadRollbackRecords();
        loadRollbackGenerations();
      });
      // 「立即回滚」手动触发：先二次确认，再弹出「世代选择」窗口（不能"不问就滚"）
      var manualBtn = page.querySelector('[data-action="rollback-manual"]');
      if (manualBtn) manualBtn.addEventListener('click', function() {
        var ok = window.confirm(
          '确定要立即回滚吗？\n\n' +
          '将基于所选世代快照，恢复受保护目录中被修改/加密的文件（按原路径写回原内容）。' +
          '确认后将再让您选择要回滚到的世代（默认最新）。'
        );
        if (!ok) return;
        if (pyBridge && pyBridge.rollbackTriggerManual) {
          pyBridge.rollbackTriggerManual();
          var st2 = document.getElementById('rollback-status-text');
          if (st2) st2.textContent = '选择世代中...';
        }
      });
      try {
        if (pyBridge && pyBridge.getRollbackProtectedDirs) {
          var raw = pyBridge.getRollbackProtectedDirs();
          var obj = (typeof raw === 'string') ? JSON.parse(raw) : raw;
          var dirsEl = document.getElementById('rollback-dirs-summary');
          if (dirsEl && obj && obj.dirs) {
            dirsEl.textContent = '保护 ' + obj.dirs.length + ' 个目录';
          }
        }
        loadRollbackGenerations();
      } catch(e) {}
    }

    // ========================================================================
    // ===== 子页面 1：隔离区管理 =====
    // ========================================================================
    function loadQuarantineList() {
      if (pyBridge) pyBridge.getQuarantineList();
    }

    function renderQuarantineList(data) {
      var listEl = document.getElementById('quarantine-list');
      var emptyEl = document.getElementById('quarantine-empty-state');
      var summaryEl = document.getElementById('quarantine-stats-summary');
      if (!listEl) return;
      // 清除既有行（保留空状态 div 和 template）
      var existingRows = listEl.querySelectorAll('.qrow');
      existingRows.forEach(function(r) { r.remove(); });
      var items = (data && data.items) || [];
      var stats = (data && data.stats) || {};
      var template = document.getElementById('quarantine-row-template');
      if (items.length === 0) {
        if (emptyEl) emptyEl.style.display = '';
        if (summaryEl) summaryEl.textContent = '共 0 个文件已隔离';
      } else {
        if (emptyEl) emptyEl.style.display = 'none';
        items.forEach(function(item) {
          var row = template.content.cloneNode(true);
          var rowDiv = row.querySelector('.qrow');
          rowDiv.setAttribute('data-row-id', item.id);
          var cb = row.querySelector('.row-cb');
          if (cb) cb.setAttribute('data-row-id', item.id);
          var nameCell = row.querySelector('.cell-name');
          var fileName = item.filename || '—';
          nameCell.textContent = fileName;
          nameCell.setAttribute('title', fileName);
          // 威胁类型
          var threatCell = row.querySelector('.cell-threat');
          var threatName = item.malware_name || item.reason || '未知';
          threatCell.innerHTML = '<span class="badge badge-danger">' + escapeHtml(threatName) + '</span>';
          threatCell.setAttribute('title', threatName);
          var pathCell = row.querySelector('.cell-path');
          var pathText = item.original_path || '—';
          pathCell.textContent = pathText;
          pathCell.setAttribute('title', pathText);
          var timeCell = row.querySelector('.cell-time');
          var timeText = item.quarantine_time || '—';
          timeCell.textContent = timeText;
          timeCell.setAttribute('title', timeText);
          // 状态徽章
          var statusCell = row.querySelector('.cell-status');
          var statusText = item.status === 'quarantined' ? '已隔离' :
                           item.status === 'restored' ? '已恢复' :
                           item.status === 'deleted' ? '已删除' : item.status;
          var statusClass = item.status === 'quarantined' ? 'badge-warning' :
                            item.status === 'restored' ? 'badge-safe' :
                            'badge-info';
          statusCell.innerHTML = '<span class="badge ' + statusClass + '">' + escapeHtml(statusText) + '</span>';
          listEl.appendChild(row);
        });
        if (summaryEl) {
          var total = stats.total || items.length;
          summaryEl.textContent = '共 ' + total + ' 个文件已隔离';
        }
      }
      // 重置选择状态
      updateQuarantineSelection();
      if (window.lucide) lucide.createIcons();
    }

    function updateQuarantineSelection() {
      var checkboxes = document.querySelectorAll('#quarantine-list .row-cb');
      var selected = 0;
      checkboxes.forEach(function(cb) {
        if (cb.checked) selected++;
      });
      var infoEl = document.getElementById('quarantine-selection-info');
      if (infoEl) infoEl.textContent = '已选 ' + selected + ' 项';
      // 启用/禁用工具栏按钮
      var restoreBtn = document.querySelector('#page-tool-quarantine [data-action="restore"]');
      var deleteBtn = document.querySelector('#page-tool-quarantine [data-action="delete"]');
      var whitelistBtn = document.querySelector('#page-tool-quarantine [data-action="whitelist"]');
      var hasSelection = selected > 0;
      [restoreBtn, deleteBtn, whitelistBtn].forEach(function(btn) {
        if (!btn) return;
        if (hasSelection) {
          btn.disabled = false;
          btn.style.opacity = '1';
          btn.style.cursor = 'pointer';
        } else {
          btn.disabled = true;
          btn.style.opacity = '0.4';
          btn.style.cursor = 'not-allowed';
        }
      });
      // 全选复选框状态
      var selectAllCb = document.getElementById('select-all-cb');
      if (selectAllCb) {
        selectAllCb.checked = checkboxes.length > 0 && selected === checkboxes.length;
      }
    }

    function executeQuarantineAction(action) {
      var checkboxes = document.querySelectorAll('#quarantine-list .row-cb:checked');
      if (checkboxes.length === 0) return;
      var ids = [];
      checkboxes.forEach(function(cb) {
        var id = cb.getAttribute('data-row-id');
        if (id !== null) ids.push(parseInt(id, 10));
      });
      if (!pyBridge || ids.length === 0) return;

      // 白名单操作走批量接口
      if (action === 'whitelist') {
        try {
          var resultJson = pyBridge.addQuarantineItemsToWhitelistBatch(JSON.stringify(ids));
          console.log('[WHITELIST] addQuarantineItemsToWhitelistBatch raw=', typeof resultJson, resultJson);
          var result = null;
          try { result = (typeof resultJson === 'string') ? JSON.parse(resultJson) : resultJson; } catch(e) {
            console.warn('[WHITELIST] 批量返回值解析失败，依赖信号接收结果:', e, resultJson);
          }
          // 结果Toast主要通过 whitelistAddResult 信号显示
          // 仅当返回值解析成功时，作为兜底额外显示一次（优先级低于"操作失败"误报）
          if (result && result.success !== undefined) {
            if (result.success) {
              showInfoToast('添加到白名单', result.message || '操作完成', 'success', 2000);
              // 处置成功 → 同时清除主界面盾牌"设备面临风险"标记
              if (typeof dashboardMarkThreatResolved === 'function') {
                dashboardMarkThreatResolved();
              }
            } else if (result.message) {
              showInfoToast('添加到白名单', result.message, 'warning', 3000);
            }
          }
          // 否则完全依赖信号显示Toast（主路径），避免"操作失败"误报
        } catch(e) {
          console.error('addQuarantineItemsToWhitelistBatch 调用失败:', e);
          showInfoToast('添加到白名单', '调用失败: ' + e.message, 'danger', 3500);
        }
        // 操作完成后刷新列表
        setTimeout(function() { loadQuarantineList(); }, 300);
        return;
      }

      var methodName = action === 'restore' ? 'restoreQuarantineItemsBatch' : 'deleteQuarantineItemsBatch';
      try {
        // 批量操作在后台线程执行，立即返回，结果通过 quarantineBatchResult 信号传递
        pyBridge[methodName](JSON.stringify(ids));
      } catch(e) {
        console.error(methodName + ' 调用失败:', e);
        showInfoToast('隔离区操作', '调用失败: ' + e.message, 'danger', 3500);
      }
      // 列表刷新由 quarantineBatchResult 信号回调处理，无需此处 setTimeout
    }

    var _quarantinePageInitialized = false;
    function initQuarantinePage() {
      if (_quarantinePageInitialized) return;
      var page = document.getElementById('page-tool-quarantine');
      if (!page) return;
      _quarantinePageInitialized = true;
      // 全选复选框（表头）
      var selectAllCb = document.getElementById('select-all-cb');
      if (selectAllCb) {
        selectAllCb.addEventListener('change', function() {
          var checked = this.checked;
          document.querySelectorAll('#quarantine-list .row-cb').forEach(function(cb) {
            cb.checked = checked;
          });
          updateQuarantineSelection();
        });
      }
      // 工具栏"全选"按钮：切换全选/取消全选
      var selectAllBtn = page.querySelector('[data-action="select-all"]');
      if (selectAllBtn) {
        selectAllBtn.addEventListener('click', function() {
          var checkboxes = document.querySelectorAll('#quarantine-list .row-cb');
          if (checkboxes.length === 0) return;
          // 若当前已全部选中则取消全选，否则全选
          var allChecked = true;
          checkboxes.forEach(function(cb) { if (!cb.checked) allChecked = false; });
          checkboxes.forEach(function(cb) { cb.checked = !allChecked; });
          if (selectAllCb) selectAllCb.checked = !allChecked;
          updateQuarantineSelection();
        });
      }
      // 工具栏按钮
      var restoreBtn = page.querySelector('[data-action="restore"]');
      if (restoreBtn) restoreBtn.addEventListener('click', function() {
        if (this.disabled) return;
        executeQuarantineAction('restore');
      });
      var deleteBtn = page.querySelector('[data-action="delete"]');
      if (deleteBtn) deleteBtn.addEventListener('click', function() {
        if (this.disabled) return;
        executeQuarantineAction('delete');
      });
      var whitelistBtn = page.querySelector('[data-action="whitelist"]');
      if (whitelistBtn) whitelistBtn.addEventListener('click', function() {
        if (this.disabled) return;
        executeQuarantineAction('whitelist');
      });
      // 行内按钮（事件委托）
      var listEl = document.getElementById('quarantine-list');
      if (listEl) {
        listEl.addEventListener('click', function(e) {
          var btn = e.target.closest('[data-row-action]');
          if (!btn) return;
          var row = btn.closest('.qrow');
          if (!row) return;
          var id = parseInt(row.getAttribute('data-row-id'), 10);
          if (isNaN(id)) return;
          var action = btn.getAttribute('data-row-action');
          if (!pyBridge) return;
          // 行内白名单按钮：单独添加到白名单
          if (action === 'whitelist') {
            try {
              var resultJson = pyBridge.addQuarantineItemToWhitelist(id);
              console.log('[WHITELIST] addQuarantineItemToWhitelist raw=', typeof resultJson, resultJson);
              var result = null;
              try { result = (typeof resultJson === 'string') ? JSON.parse(resultJson) : resultJson; } catch(e) {
                console.warn('[WHITELIST] 返回值解析失败，依赖信号接收结果:', e, resultJson);
              }
              // 注意：结果Toast主要通过 whitelistAddResult 信号显示（更可靠，避免返回值序列化问题）
              // 这里仅在返回值解析成功且信号未及时触发时作为兜底显示
              if (result && result.success !== undefined) {
                // 兜底：如果信号监听可能丢失，仍通过返回值显示一次
                // （轻微的双Toast风险可接受，优先级低于"操作失败"误报）
                if (result.success) {
                  showInfoToast('添加到白名单', result.message || '操作完成',
                                result.skipped ? 'info' : 'success', 2000);
                  // 处置成功 → 清除主界面盾牌"设备面临风险"标记
                  if (typeof dashboardMarkThreatResolved === 'function') {
                    dashboardMarkThreatResolved();
                  }
                } else if (result.message) {
                  showInfoToast('添加到白名单', result.message, 'warning', 3000);
                }
              }
              // 否则完全依赖信号显示Toast（主路径），避免"操作失败"误报
            } catch(err) {
              console.error('行内白名单操作失败:', err);
              showInfoToast('添加到白名单', '调用失败: ' + err.message, 'danger', 3500);
            }
            setTimeout(function() { loadQuarantineList(); }, 300);
            return;
          }
          try {
            var methodName = action === 'restore' ? 'restoreQuarantineItem' : 'deleteQuarantineItem';
            pyBridge[methodName](id);
            // 单条处置完成 → 清除主界面盾牌"设备面临风险"标记
            if (typeof dashboardMarkThreatResolved === 'function') {
              dashboardMarkThreatResolved();
            }
            setTimeout(function() { loadQuarantineList(); }, 300);
          } catch(err) { console.error('行内操作失败:', err); }
        });
        // 行复选框变化
        listEl.addEventListener('change', function(e) {
          if (e.target.classList.contains('row-cb')) updateQuarantineSelection();
        });
      }
    }

    // ========================================================================
    // ===== 子页面 2：导入签名库 =====
    // ========================================================================
    function loadSignatureSummary() {
      if (pyBridge) pyBridge.getSignatureSummary();
    }

    function renderSignatureSummary(data) {
      if (!data) return;
      var malwareEl = document.getElementById('sig-count-malware');
      var heurEl = document.getElementById('sig-count-heuristics');
      var whitelistEl = document.getElementById('sig-count-whitelist');
      var statusBadge = document.getElementById('sig-status-badge');
      if (malwareEl && typeof data.count === 'number') {
        malwareEl.textContent = data.count.toLocaleString();
      }
      if (heurEl && typeof data.heuristics_count === 'number') {
        heurEl.textContent = data.heuristics_count.toLocaleString();
      }
      if (whitelistEl && typeof data.whitelist_count === 'number') {
        whitelistEl.textContent = data.whitelist_count.toLocaleString();
      }
      if (statusBadge && data.lastUpdate) {
        statusBadge.textContent = '更新于 ' + data.lastUpdate;
      }
    }

    function appendSigLog(message, level) {
      var logArea = document.getElementById('sig-log-area');
      if (!logArea) return;
      var now = new Date();
      var ts = String(now.getHours()).padStart(2, '0') + ':' +
               String(now.getMinutes()).padStart(2, '0') + ':' +
               String(now.getSeconds()).padStart(2, '0');
      var color = 'var(--psls-muted-foreground)';
      if (level === 'success') color = 'var(--psls-success)';
      else if (level === 'warn') color = 'var(--psls-warning)';
      else if (level === 'error') color = 'var(--psls-danger)';
      else if (level === 'info') color = 'var(--psls-info)';
      var line = document.createElement('div');
      line.className = 'sig-log-line';
      line.style.cssText = 'line-height:1.55;';
      line.innerHTML = '<span style="color:var(--psls-muted-foreground);">[' + ts + ']</span> ' +
                       '<span style="color:' + color + ';">' + escapeHtml(message) + '</span>';
      logArea.appendChild(line);
      logArea.scrollTop = logArea.scrollHeight;
    }

    function updateImportProgress(percent, message) {
      var fill = document.getElementById('sig-progress-fill');
      var pct = document.getElementById('sig-progress-pct');
      var status = document.getElementById('sig-progress-status');
      if (fill) fill.style.width = (percent || 0) + '%';
      if (pct) pct.textContent = (percent || 0) + '%';
      if (status) {
        status.textContent = message || '导入中...';
        if (percent >= 100) {
          status.style.backgroundColor = 'var(--psls-c-success-12)';
          status.style.color = 'var(--psls-success)';
        }
      }
      if (message) appendSigLog(message, percent >= 100 ? 'success' : 'info');
    }

    function onImportFinished(added, total, success) {
      var startBtn = document.querySelector('#page-tool-signatures [data-action="start-import"]');
      var stopBtn = document.querySelector('#page-tool-signatures [data-action="stop-import"]');
      if (startBtn) {
        startBtn.disabled = false;
        startBtn.style.opacity = '1';
        startBtn.style.cursor = 'pointer';
      }
      if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.style.opacity = '0.45';
        stopBtn.style.cursor = 'not-allowed';
      }

      // 解除左侧导航和扫描选项的锁定
      _importInProgress = false;
      document.querySelectorAll('.nav-link').forEach(function(link) {
        link.style.pointerEvents = '';
        link.style.opacity = '';
      });

      if (success) {
        appendSigLog('识别完成: 新增 ' + added + ' 个签名，共 ' + total + ' 个', 'success');
      } else {
        appendSigLog('识别失败', 'error');
      }
      // 刷新签名库摘要（白名单/启发式规则数）
      loadSignatureSummary();
    }

    // 当前签名页面模式：'signature'（签名库导入）或 'virus'（病毒样本识别）
    var _currentSigMode = 'signature';
    // 签名库导入内部模式：'file'（文件直接导入）或 'samples'（样本目录批量导入）
    var _sigImportSubMode = 'file';
    // 导入进行中标志（阻止导航离开）
    var _importInProgress = false;

    function onSigImportModeChange(mode) {
      _sigImportSubMode = mode;
      // 同步隐藏 radio 的选中状态（保证与点击的 span 一致）
      document.querySelectorAll('input[name="sig-import-mode"]').forEach(function(r) {
        r.checked = (r.value === mode);
      });
      var btnFile = document.getElementById('sig-mode-btn-file');
      var btnSamples = document.getElementById('sig-mode-btn-samples');
      var hint = document.getElementById('sig-mode-switch-hint');
      var sourceTitle = document.getElementById('sig-source-title');
      var modeHint = document.getElementById('sig-mode-hint');
      var pathInput = document.getElementById('sig-path-input');
      var startBtnText = document.getElementById('sig-start-btn-text');
      var bottomHint = document.getElementById('sig-bottom-hint');
      if (mode === 'file') {
        if (btnFile) { btnFile.style.background = 'var(--psls-primary)'; btnFile.style.color = 'white'; btnFile.style.fontWeight = '600'; }
        if (btnSamples) { btnSamples.style.background = 'transparent'; btnSamples.style.color = 'var(--psls-muted-foreground)'; btnSamples.style.fontWeight = '500'; }
        if (hint) hint.textContent = '直接读取 .json / .db / .txt 签名库文件';
        if (sourceTitle) sourceTitle.textContent = '选择签名库文件';
        if (modeHint) modeHint.textContent = '支持 .json / .db / .txt 签名库文件，直接导入签名数据';
        if (pathInput) pathInput.placeholder = '未选择 — 点击右侧按钮浏览签名库文件';
        if (startBtnText) startBtnText.textContent = '开始导入';
        if (bottomHint) bottomHint.textContent = '签名库文件直接导入签名数据';
      } else {
        if (btnFile) { btnFile.style.background = 'transparent'; btnFile.style.color = 'var(--psls-muted-foreground)'; btnFile.style.fontWeight = '500'; }
        if (btnSamples) { btnSamples.style.background = 'var(--psls-primary)'; btnSamples.style.color = 'white'; btnSamples.style.fontWeight = '600'; }
        if (hint) hint.textContent = '扫描恶意样本文件目录，计算 SHA256 后批量入库';
        if (sourceTitle) sourceTitle.textContent = '选择恶意样本目录';
        if (modeHint) modeHint.textContent = '递归扫描目录中所有样本文件，自动解析威胁名称和类型';
        if (pathInput) pathInput.placeholder = '未选择 — 点击右侧按钮浏览样本文件目录';
        if (startBtnText) startBtnText.textContent = '开始导入';
        if (bottomHint) bottomHint.textContent = '从样本目录计算哈希并批量导入签名数据库';
      }
    }

    function startSignatureImport() {
      var pathInput = document.getElementById('sig-path-input');
      if (!pathInput || !pathInput.value) {
        if (typeof showInfoToast === 'function') {
          showInfoToast('提示', '请先选择文件或目录', 'warning');
        } else {
          appendSigLog('请先选择文件或目录', 'warn');
        }
        return;
      }
      var path = pathInput.value;
      var startBtn = document.querySelector('[data-action="start-import"]');
      var stopBtn = document.querySelector('[data-action="stop-import"]');
      if (startBtn) { startBtn.disabled = true; startBtn.style.opacity = '0.45'; startBtn.style.cursor = 'not-allowed'; }
      if (stopBtn) { stopBtn.disabled = false; stopBtn.style.opacity = '1'; stopBtn.style.cursor = 'pointer'; }
      var statusBadge = document.getElementById('sig-progress-status');
      if (statusBadge) { statusBadge.textContent = '进行中'; statusBadge.style.backgroundColor = 'var(--psls-c-accent-10)'; statusBadge.style.color = 'var(--psls-primary)'; }
      var modeDesc = '';
      if (_currentSigMode === 'signature') {
        modeDesc = _sigImportSubMode === 'samples' ? '样本目录批量导入' : '导入签名库';
      } else if (_currentSigMode === 'whitelist') {
        modeDesc = '导入白名单';
      } else {
        modeDesc = '识别病毒样本';
      }
      appendSigLog('开始' + modeDesc + '...', 'info');

      // 锁定左侧导航和扫描选项，禁止导入期间操作其他功能
      _importInProgress = true;
      document.querySelectorAll('.nav-link').forEach(function(link) {
        link.style.pointerEvents = 'none';
        link.style.opacity = '0.5';
      });

      if (_currentSigMode === 'signature') {
        if (_sigImportSubMode === 'samples') {
          if (pyBridge) pyBridge.importSampleDir(path);
        } else {
          if (pyBridge) pyBridge.importSignatureFile(path);
        }
      } else if (_currentSigMode === 'whitelist') {
        if (pyBridge) pyBridge.importWhitelistFile(path);
      } else {
        var forceChk = document.getElementById('force-import');
        var forceVal = (forceChk && forceChk.checked) ? 'true' : 'false';
        if (pyBridge) pyBridge.importVirusSamples(path, forceVal);
      }
    }

    // ========================================================================
    // ===== 子页面：MalwareBazaar 样本更新 =====
    // ========================================================================
    var _mbRunning = false;
    var _mbBenignDirs = [];

    function initMBPage() {
      var startBtn = document.getElementById('mb-start-btn');
      if (!startBtn || startBtn.getAttribute('data-init')) return;
      startBtn.setAttribute('data-init', '1');
      var stopBtn = document.getElementById('mb-stop-btn');
      var monthlyBtn = document.getElementById('mb-monthly-btn');
      var browseBtn = document.getElementById('mb-benign-browse');
      var addBtn = document.getElementById('mb-benign-add');
      var benignInput = document.getElementById('mb-benign-input');
      var clearBtn = document.getElementById('mb-clear-log');
      if (startBtn) startBtn.addEventListener('click', startMBSync);
      if (monthlyBtn) monthlyBtn.addEventListener('click', startMBMonthlySync);
      if (stopBtn) stopBtn.addEventListener('click', stopMBSync);
      if (clearBtn) clearBtn.addEventListener('click', clearMBLog);
      // 良性目录：添加/回车/浏览（浏览回填后自动添加，交互同扫描排除项）
      if (addBtn && benignInput) {
        addBtn.addEventListener('click', function() { addMBBenignDir(); });
        benignInput.addEventListener('keydown', function(e) {
          if (e.key === 'Enter') { addMBBenignDir(); }
        });
      }
      if (browseBtn) {
        browseBtn.addEventListener('click', function() {
          if (pyBridge) {
            pyBridge.setBrowseTarget('mb-benign-input');
            pyBridge.browseFolder();
            setTimeout(function() {
              if (benignInput && benignInput.value.trim()) addMBBenignDir();
            }, 200);
          }
        });
      }
      // 恢复已保存配置
      try {
        var saved = localStorage.getItem('psls_mb_config');
        if (saved) {
          var cfg = JSON.parse(saved) || {};
          var rt = document.getElementById('mb-retrain');
          if (rt) rt.checked = !!cfg.retrain;
          var ay = document.getElementById('mb-auto-yara');
          if (ay) ay.checked = !!cfg.auto_yara;
          _mbBenignDirs = (cfg.benign_dirs || [])
            .filter(function(p) { return typeof p === 'string' && p.trim(); })
            .map(function(p) { return p.trim(); });
          renderMBBenignList();
        }
      } catch(e) { /* localStorage 不可用时忽略 */ }
    }

    function addMBBenignDir() {
      var input = document.getElementById('mb-benign-input');
      if (!input) return;
      var val = input.value.trim();
      if (!val) return;
      if (_mbBenignDirs.indexOf(val) === -1) {
        _mbBenignDirs.push(val);
      }
      input.value = '';
      renderMBBenignList();
      saveMBBenignDirs();
    }

    function renderMBBenignList() {
      var listEl = document.getElementById('mb-benign-list');
      if (!listEl) return;
      listEl.innerHTML = '';
      if (_mbBenignDirs.length === 0) {
        var empty = document.createElement('div');
        empty.style.cssText = 'font-size:12px; color:var(--psls-muted-foreground); padding:4px 0;';
        empty.textContent = '暂无良性样本目录';
        listEl.appendChild(empty);
        return;
      }
      _mbBenignDirs.forEach(function(path, idx) {
        var row = document.createElement('div');
        row.className = 'flex items-center gap-2';
        row.style.cssText = 'padding:4px 8px; border-radius:4px; background-color:var(--psls-muted);';
        var span = document.createElement('span');
        span.className = 'flex-1 text-xs';
        span.style.cssText = 'color:var(--psls-card-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
        span.title = path;
        span.textContent = path;
        var delBtn = document.createElement('button');
        delBtn.className = 'text-xs';
        delBtn.style.cssText = 'color:var(--psls-c-tool-mb); background:transparent; border:none; cursor:pointer; padding:2px 6px; font-weight:600;';
        delBtn.textContent = '删除';
        delBtn.addEventListener('click', function() {
          _mbBenignDirs.splice(idx, 1);
          renderMBBenignList();
          saveMBBenignDirs();
        });
        row.appendChild(span);
        row.appendChild(delBtn);
        listEl.appendChild(row);
      });
    }

    function saveMBBenignDirs() {
      try {
        var saved = JSON.parse(localStorage.getItem('psls_mb_config') || '{}') || {};
        saved.benign_dirs = _mbBenignDirs;
        localStorage.setItem('psls_mb_config', JSON.stringify(saved));
      } catch(e) { /* 忽略 */ }
    }

    function loadMBStatus() {
      if (pyBridge) pyBridge.mbGetStatus('');
    }

    function handleMBStatus(st) {
      var el;
      if ((el = document.getElementById('mb-stat-signatures'))) el.textContent = st.signature_count || 0;
      if ((el = document.getElementById('mb-stat-days'))) el.textContent = st.synced_count || 0;
      if ((el = document.getElementById('mb-stat-latest'))) el.textContent = st.last_synced || '--';
      var lc = st.last_check ? String(st.last_check).replace('T', ' ').slice(5, 16) : '--';
      if ((el = document.getElementById('mb-stat-lastsync'))) el.textContent = lc;
      var badge = document.getElementById('mb-status-badge');
      if (badge) {
        if (st.last_synced) {
          badge.textContent = '已同步至 ' + st.last_synced;
          badge.style.backgroundColor = 'var(--psls-c-tool-mb-12)';
          badge.style.color = 'var(--psls-c-tool-mb)';
        } else {
          badge.textContent = '尚未同步';
          badge.style.backgroundColor = 'var(--psls-warning-tint)';
          badge.style.color = 'var(--psls-warning)';
        }
      }
      var cardBadge = document.getElementById('mb-card-badge');
      if (cardBadge) cardBadge.textContent = st.last_synced || '未同步';
    }

    function updateMBProgress(obj) {
      var percent = Math.max(0, Math.min(100, parseInt(obj.percent, 10) || 0));
      var msg = obj.message || '';
      var stage = obj.stage || '';
      var fill = document.getElementById('mb-progress-fill');
      var pctEl = document.getElementById('mb-progress-pct');
      var msgEl = document.getElementById('mb-progress-msg');
      var statusEl = document.getElementById('mb-progress-status');
      if (fill) fill.style.width = percent + '%';
      if (pctEl) pctEl.textContent = percent + '%';
      if (msgEl) msgEl.textContent = msg;
      if (statusEl) {
        statusEl.textContent = (stage === 'train') ? '训练中' :
          (stage === 'download' || stage === 'extract' || stage === 'import') ? '同步中' :
          (stage === 'done') ? '完成' : '进行中';
        statusEl.style.backgroundColor = 'var(--psls-c-tool-mb-12)';
        statusEl.style.color = 'var(--psls-c-tool-mb)';
      }
      appendMBLog(msg, 'info');
      _mbRunning = true;
      setMBRunningUI(true);
    }

    function handleMBFinished(res) {
      _mbRunning = false;
      setMBRunningUI(false);
      var fill = document.getElementById('mb-progress-fill');
      var statusEl = document.getElementById('mb-progress-status');
      var msgEl = document.getElementById('mb-progress-msg');
      if (res.busy) {
        if (statusEl) { statusEl.textContent = '忙碌'; statusEl.style.backgroundColor = 'var(--psls-warning-tint)'; statusEl.style.color = 'var(--psls-warning)'; }
        if (msgEl) msgEl.textContent = res.message || '已有任务运行中';
        appendMBLog('忙碌: ' + (res.message || '已有任务运行中'), 'warn');
        return;
      }
      if (res.ok) {
        if (fill) fill.style.width = '100%';
        if (statusEl) { statusEl.textContent = '完成'; statusEl.style.backgroundColor = 'var(--psls-c-success-12)'; statusEl.style.color = 'var(--psls-success)'; }
        if (msgEl) msgEl.textContent = res.message || '同步完成';
        appendMBLog((res.message || '同步完成'), 'success');
        if (typeof showInfoToast === 'function') {
          showInfoToast('样本更新', res.message || '同步完成', 'success', 2500);
        }
        // 训练完成提示
        if (res.retrained) {
          appendMBLog('LightGBM 模型已重训并生效', 'success');
        }
        setTimeout(loadMBStatus, 300);
      } else if (res.stopped) {
        if (statusEl) { statusEl.textContent = '已停止'; statusEl.style.backgroundColor = 'var(--psls-warning-tint)'; statusEl.style.color = 'var(--psls-warning)'; }
        if (msgEl) msgEl.textContent = res.message || '同步已停止';
        appendMBLog('已停止: ' + (res.message || ''), 'warn');
      } else {
        if (statusEl) { statusEl.textContent = '失败'; statusEl.style.backgroundColor = 'var(--psls-c-cat-process-12)'; statusEl.style.color = 'var(--psls-danger)'; }
        if (msgEl) msgEl.textContent = res.message || '同步失败';
        appendMBLog((res.message || '同步失败'), 'error');
        if (typeof showInfoToast === 'function') {
          showInfoToast('样本更新', res.message || '同步失败', 'error', 3500);
        }
      }
    }

    function startMBSync() {
      var rtInput = document.getElementById('mb-retrain');
      var retrain = !!(rtInput && rtInput.checked);
      var ayInput = document.getElementById('mb-auto-yara');
      var autoYara = !!(ayInput && ayInput.checked);
      // 良性目录：以已添加列表为准，输入框残留内容一并并入
      var benignDirs = _mbBenignDirs.slice();
      var biInput = document.getElementById('mb-benign-input');
      if (biInput && biInput.value.trim() && benignDirs.indexOf(biInput.value.trim()) === -1) {
        benignDirs.push(biInput.value.trim());
      }
      try {
        localStorage.setItem('psls_mb_config', JSON.stringify({
          retrain: retrain, auto_yara: autoYara, benign_dirs: benignDirs
        }));
      } catch(e) { /* 忽略 */ }
      if (retrain && benignDirs.length === 0 && typeof showInfoToast === 'function') {
        showInfoToast('样本更新', '未配置良性样本目录，本次仅同步签名，重训将被跳过', 'warning', 2500);
      }
      if (pyBridge) {
        pyBridge.mbSyncNow(JSON.stringify({
          retrain: retrain, auto_yara: autoYara, benign_dirs: benignDirs
        }));
      }
      _mbRunning = true;
      setMBRunningUI(true);
      clearMBLog();
      appendMBLog('开始同步 Live Malware DB 每日样本（解压密码自动处理）...', 'info');
    }

    function startMBMonthlySync() {
      var rtInput = document.getElementById('mb-retrain');
      var retrain = !!(rtInput && rtInput.checked);
      var ayInput = document.getElementById('mb-auto-yara');
      var autoYara = !!(ayInput && ayInput.checked);
      var benignDirs = _mbBenignDirs.slice();
      var biInput = document.getElementById('mb-benign-input');
      if (biInput && biInput.value.trim() && benignDirs.indexOf(biInput.value.trim()) === -1) {
        benignDirs.push(biInput.value.trim());
      }
      if (pyBridge) {
        pyBridge.mbSyncMonthlyNow(JSON.stringify({
          retrain: retrain, auto_yara: autoYara, benign_dirs: benignDirs
        }));
      }
      _mbRunning = true;
      setMBRunningUI(true);
      clearMBLog();
      appendMBLog('开始同步最近月度归档包（约 3GB，解压密码自动处理）...', 'info');
    }

    function stopMBSync() {
      if (pyBridge) pyBridge.mbSyncStop('');
    }

    function setMBRunningUI(running) {
      var startBtn = document.getElementById('mb-start-btn');
      var stopBtn = document.getElementById('mb-stop-btn');
      var monthlyBtn = document.getElementById('mb-monthly-btn');
      if (startBtn) {
        startBtn.disabled = running;
        startBtn.style.opacity = running ? '0.5' : '1';
        startBtn.style.cursor = running ? 'not-allowed' : 'pointer';
      }
      if (monthlyBtn) {
        monthlyBtn.disabled = running;
        monthlyBtn.style.opacity = running ? '0.5' : '1';
        monthlyBtn.style.cursor = running ? 'not-allowed' : 'pointer';
      }
      if (stopBtn) {
        stopBtn.disabled = !running;
        stopBtn.style.opacity = running ? '1' : '0.45';
        stopBtn.style.cursor = running ? 'pointer' : 'not-allowed';
      }
    }

    function appendMBLog(text, level) {
      var logArea = document.getElementById('mb-log-area');
      if (!logArea) return;
      var now = new Date();
      var ts = String(now.getHours()).padStart(2, '0') + ':' +
               String(now.getMinutes()).padStart(2, '0') + ':' +
               String(now.getSeconds()).padStart(2, '0');
      var color = 'var(--psls-muted-foreground)';
      if (level === 'success') color = 'var(--psls-success)';
      else if (level === 'warn') color = 'var(--psls-warning)';
      else if (level === 'error') color = 'var(--psls-danger)';
      else if (level === 'info') color = 'var(--psls-info)';
      var line = document.createElement('div');
      line.className = 'mb-log-line';
      line.style.cssText = 'line-height:1.55;';
      line.innerHTML = '<span style="color:var(--psls-muted-foreground);">[' + ts + ']</span> ' +
                       '<span style="color:' + color + ';">' + escapeHtml(text) + '</span>';
      logArea.appendChild(line);
      logArea.scrollTop = logArea.scrollHeight;
    }

    function clearMBLog() {
      var logArea = document.getElementById('mb-log-area');
      if (!logArea) return;
      logArea.innerHTML = '';
      var now = new Date();
      var ts = String(now.getHours()).padStart(2, '0') + ':' +
               String(now.getMinutes()).padStart(2, '0') + ':' +
               String(now.getSeconds()).padStart(2, '0');
      var line = document.createElement('div');
      line.className = 'mb-log-line';
      line.style.cssText = 'line-height:1.55;';
      line.innerHTML = '<span style="color:var(--psls-muted-foreground);">[' + ts + ']</span> ' +
                       '<span style="color:var(--psls-muted-foreground);">等待开始...（启动后会自动检测更新）</span>';
      logArea.appendChild(line);
    }

    var _signaturesPageInitialized = false;
    function initSignaturesPage() {
      if (_signaturesPageInitialized) return;
      var page = document.getElementById('page-tool-signatures');
      if (!page) return;
      _signaturesPageInitialized = true;

      // ===== Tab 切换逻辑 =====
      var tabSig = page.querySelector('#sig-tab-signature');
      var tabVirus = page.querySelector('#sig-tab-virus');
      var tabWhitelist = page.querySelector('#sig-tab-whitelist');
      var forceContainer = page.querySelector('#force-import-container');
      var sigModeSwitchContainer = page.querySelector('#sig-mode-switch-container');
      var sourceTitle = page.querySelector('#sig-source-title');
      var modeHint = page.querySelector('#sig-mode-hint');
      var startBtnText = page.querySelector('#sig-start-btn-text');
      var bottomHint = page.querySelector('#sig-bottom-hint');
      var pathInput = page.querySelector('#sig-path-input');

      function _highlightTab(activeTab, inactiveTabs) {
        if (activeTab) {
          activeTab.style.border = '1px solid var(--psls-primary)';
          activeTab.style.backgroundColor = 'var(--psls-c-accent-10)';
          activeTab.style.color = 'var(--psls-primary)';
          activeTab.style.fontWeight = '600';
        }
        inactiveTabs.forEach(function(t) {
          if (t) {
            t.style.border = '1px solid var(--psls-border)';
            t.style.backgroundColor = 'var(--psls-card)';
            t.style.color = 'var(--psls-muted-foreground)';
            t.style.fontWeight = '500';
          }
        });
      }

      function switchSigMode(mode) {
        _currentSigMode = mode;
        if (mode === 'signature') {
          _highlightTab(tabSig, [tabVirus, tabWhitelist]);
          if (forceContainer) forceContainer.style.display = 'none';
          if (sigModeSwitchContainer) sigModeSwitchContainer.style.display = '';
          onSigImportModeChange(_sigImportSubMode);
        } else if (mode === 'virus') {
          _highlightTab(tabVirus, [tabSig, tabWhitelist]);
          if (forceContainer) forceContainer.style.display = '';
          if (sigModeSwitchContainer) sigModeSwitchContainer.style.display = 'none';
          if (sourceTitle) sourceTitle.textContent = '选择病毒样本来源';
          if (modeHint) modeHint.textContent = '支持文件/目录/压缩包，通过病毒识别引擎分析后入库';
          if (startBtnText) startBtnText.textContent = '开始识别';
          if (bottomHint) bottomHint.textContent = '识别仅提取恶意文件特征，安全文件将被跳过';
          if (pathInput) pathInput.placeholder = '未选择 — 点击右侧按钮浏览病毒样本文件或目录';
        } else if (mode === 'whitelist') {
          _highlightTab(tabWhitelist, [tabSig, tabVirus]);
          if (forceContainer) forceContainer.style.display = 'none';
          if (sigModeSwitchContainer) sigModeSwitchContainer.style.display = 'none';
          if (sourceTitle) sourceTitle.textContent = '选择白名单来源';
          if (modeHint) modeHint.textContent = '仅支持精确哈希（SHA256）：文件夹/文件自动算哈希，或 .json/.txt 直接读哈希列表';
          if (startBtnText) startBtnText.textContent = '开始导入';
          if (bottomHint) bottomHint.textContent = '仅精确哈希匹配；不支持模糊哈希、YARA 规则和数据库导入';
          if (pathInput) pathInput.placeholder = '未选择 — 点击右侧按钮浏览白名单文件或目录';
        }
      }

      if (tabSig) tabSig.addEventListener('click', function() { switchSigMode('signature'); });
      if (tabVirus) tabVirus.addEventListener('click', function() { switchSigMode('virus'); });
      if (tabWhitelist) tabWhitelist.addEventListener('click', function() { switchSigMode('whitelist'); });

      // ===== 浏览文件按钮：根据模式选择不同 target =====
      var browseFileBtn = page.querySelector('[data-action="browse-file"]');
      if (browseFileBtn) browseFileBtn.addEventListener('click', function() {
        if (_currentSigMode === 'signature' && _sigImportSubMode === 'samples') {
          pyBridge.setBrowseTarget('sig-path-input');
          pyBridge.browseFolder();
        } else if (_currentSigMode === 'signature') {
          if (pyBridge) pyBridge.selectSingleFile('signature');
        } else if (_currentSigMode === 'whitelist') {
          if (pyBridge) pyBridge.selectSingleFile('whitelist');
        } else {
          if (pyBridge) pyBridge.selectSingleFile('virus');
        }
      });
      var browseDirBtn = page.querySelector('[data-action="browse-dir"]');
      if (browseDirBtn) browseDirBtn.addEventListener('click', function() {
        if (pyBridge) {
          pyBridge.setBrowseTarget('sig-path-input');
          pyBridge.browseFolder();
        }
      });
      var startBtn = page.querySelector('[data-action="start-import"]');
      if (startBtn) startBtn.addEventListener('click', startSignatureImport);
      var stopBtn = page.querySelector('[data-action="stop-import"]');
      if (stopBtn) stopBtn.addEventListener('click', function() {
        if (pyBridge) pyBridge.stopSignatureImport();
      });
      var viewBtn = page.querySelector('[data-action="view-signatures"]');
      if (viewBtn) viewBtn.addEventListener('click', function() {
        navigateTo('tool-sigviewer');
      });
      var clearLogBtn = page.querySelector('[data-action="clear-sig-log"]');
      if (clearLogBtn) clearLogBtn.addEventListener('click', function() {
        var logArea = document.getElementById('sig-log-area');
        if (logArea) logArea.innerHTML = '<div class="sig-log-line" style="line-height:1.55;"><span style="color:var(--psls-muted-foreground);">[--:--:--]</span> 日志已清空</div>';
      });

      // ===== 导出数据库按钮 =====
      var exportBtn = page.querySelector('[data-action="export-db"]');
      if (exportBtn) exportBtn.addEventListener('click', function() {
        if (pyBridge && pyBridge.exportSignatureDBDialog) {
          appendSigLog('请选择导出文件保存位置...', 'info');
          pyBridge.exportSignatureDBDialog();
        }
      });

      // ===== 导出完成信号 =====
      if (pyBridge && pyBridge.exportFinished) {
        pyBridge.exportFinished.connect(function(success) {
          if (success) {
            appendSigLog('签名库导出成功', 'success');
            showInfoToast('签名库导出成功', 'success');
          } else {
            appendSigLog('签名库导出失败', 'error');
            showInfoToast('签名库导出失败', 'error');
          }
        });
      }
    }

    // ========================================================================
    // ===== 子页面 2.5：病毒库查看 =====
    // ========================================================================
    // 病毒库查看页面状态
    var sigViewerState = {
      category: 'malware',     // 'malware' / 'heuristic' / 'whitelist'
      page: 1,
      pageSize: 20,
      search: '',
      total: 0,
      selectedKeys: new Set()  // 当前页选中的 key 集合
    };

    function loadSignatureViewer() {
      // 默认进入恶意软件签名标签
      sigViewerState.page = 1;
      sigViewerState.search = '';
      sigViewerState.selectedKeys.clear();
      var searchInput = document.getElementById('sig-search-input');
      if (searchInput) searchInput.value = '';
      switchSigTab('malware');
    }

    function switchSigTab(category) {
      sigViewerState.category = category;
      sigViewerState.page = 1;
      sigViewerState.selectedKeys.clear();
      // 更新标签按钮高亮
      document.querySelectorAll('.sig-tab-btn').forEach(function(btn) {
        if (btn.getAttribute('data-sig-tab') === category) {
          btn.style.backgroundColor = 'var(--psls-card)';
          btn.style.color = 'var(--psls-primary)';
          btn.style.fontWeight = '600';
        } else {
          btn.style.backgroundColor = 'transparent';
          btn.style.color = 'var(--psls-muted-foreground)';
          btn.style.fontWeight = '500';
        }
      });
      // 切换表头显示
      ['malware', 'heuristic', 'whitelist'].forEach(function(cat) {
        var header = document.getElementById('sig-header-' + cat);
        if (header) header.style.display = (cat === category) ? 'flex' : 'none';
      });
      // 搜索框 placeholder 调整
      var searchInput = document.getElementById('sig-search-input');
      if (searchInput) {
        if (category === 'malware') {
          searchInput.placeholder = '搜索名称/哈希/类型/来源...';
        } else if (category === 'heuristic') {
          searchInput.placeholder = '搜索规则名称/类型...';
        } else {
          searchInput.placeholder = '搜索哈希/原因...';
        }
      }
      // 重置白名单按钮：仅在白名单标签页显示
      var clearWlBtn = document.getElementById('sig-clear-whitelist-btn');
      if (clearWlBtn) {
        clearWlBtn.style.display = (category === 'whitelist') ? 'flex' : 'none';
      }
      loadSigViewerPage();
    }

    function loadSigViewerPage() {
      if (!pyBridge) return;
      try {
        pyBridge.getSignatureList(sigViewerState.page, sigViewerState.pageSize, sigViewerState.category, sigViewerState.search);
      } catch(e) {
        console.error('getSignatureList 调用失败:', e);
      }
      // 显示加载中状态
      var listEl = document.getElementById('sig-list');
      var emptyEl = document.getElementById('sig-empty-state');
      if (listEl && emptyEl && listEl.querySelectorAll('.sigrow').length === 0) {
        emptyEl.style.display = '';
        emptyEl.innerHTML =
          '<div class="flex items-center justify-center" style="width:72px; height:72px; border-radius:50%; background-color:var(--psls-c-cat-file-08); margin-bottom:16px;">' +
            '<i data-lucide="loader-2" style="width:34px;height:34px; color:var(--psls-info); opacity:0.7;" class="lucide-spin"></i>' +
          '</div>' +
          '<div style="font-size:14px; color:var(--psls-muted-foreground);">加载中...</div>';
        if (window.lucide) lucide.createIcons();
      }
    }

    function renderSignatureList(data) {
      var listEl = document.getElementById('sig-list');
      var emptyEl = document.getElementById('sig-empty-state');
      var summaryEl = document.getElementById('sig-viewer-summary');
      var pageEl = document.getElementById('sig-page-info');
      if (!listEl) return;

      // 错误处理
      if (data.error) {
        if (emptyEl) {
          emptyEl.style.display = '';
          emptyEl.innerHTML =
            '<div class="flex items-center justify-center mb-4" style="width:72px; height:72px; border-radius:50%; background-color:var(--psls-c-danger-10);">' +
              '<i data-lucide="alert-triangle" style="width:34px;height:34px; color:var(--psls-danger);"></i>' +
            '</div>' +
            '<div style="font-size:15px; font-weight:600; color:var(--psls-foreground); margin-bottom:6px;">加载失败</div>' +
            '<div style="font-size:13px; color:var(--psls-danger);">' + escapeHtml(data.error) + '</div>';
        }
        if (window.lucide) lucide.createIcons();
        return;
      }

      // 清除既有行
      var existingRows = listEl.querySelectorAll('.sigrow');
      existingRows.forEach(function(r) { r.remove(); });

      var items = (data && data.items) || [];
      var total = (data && data.total) || 0;
      var page = (data && data.page) || 1;
      var pageSize = (data && data.pageSize) || sigViewerState.pageSize;
      var category = (data && data.category) || sigViewerState.category;

      sigViewerState.total = total;
      sigViewerState.page = page;
      sigViewerState.pageSize = pageSize;
      sigViewerState.category = category;

      if (items.length === 0) {
        if (emptyEl) {
          emptyEl.style.display = '';
          var emptyIcon = category === 'malware' ? 'database' :
                          category === 'heuristic' ? 'git-branch' : 'shield-check';
          var emptyText = category === 'malware' ? '导入病毒样本后，签名将显示在此处' :
                          category === 'heuristic' ? '启发式规则为空' : '白名单为空';
          emptyEl.innerHTML =
            '<div class="flex items-center justify-center" style="width:72px; height:72px; border-radius:50%; background-color:var(--psls-c-cat-file-08); margin-bottom:16px;">' +
              '<i data-lucide="' + emptyIcon + '" style="width:34px;height:34px; color:var(--psls-info); opacity:0.7;"></i>' +
            '</div>' +
            '<div style="font-size:16px; font-weight:600; color:var(--psls-foreground); margin-bottom:6px;">暂无数据</div>' +
            '<div style="font-size:13px; color:var(--psls-muted-foreground);">' + escapeHtml(emptyText) + '</div>';
        }
      } else {
        if (emptyEl) emptyEl.style.display = 'none';
        items.forEach(function(item) {
          var row = buildSigRow(item, category);
          if (row) listEl.appendChild(row);
        });
      }

      // 更新统计与分页信息
      if (summaryEl) {
        var totalPages = Math.max(1, Math.ceil(total / pageSize));
        summaryEl.textContent = '共 ' + total + ' 条记录 · 第 ' + page + ' / ' + totalPages + ' 页';
      }
      if (pageEl) {
        var totalPages2 = Math.max(1, Math.ceil(total / pageSize));
        pageEl.textContent = page + ' / ' + totalPages2;
      }
      // 翻页按钮状态
      var prevBtn = document.querySelector('#page-tool-sigviewer [data-action="sig-prev-page"]');
      var nextBtn = document.querySelector('#page-tool-sigviewer [data-action="sig-next-page"]');
      if (prevBtn) {
        prevBtn.disabled = (page <= 1);
        prevBtn.style.opacity = (page <= 1) ? '0.4' : '1';
        prevBtn.style.cursor = (page <= 1) ? 'not-allowed' : 'pointer';
      }
      if (nextBtn) {
        var totalPages3 = Math.max(1, Math.ceil(total / pageSize));
        nextBtn.disabled = (page >= totalPages3);
        nextBtn.style.opacity = (page >= totalPages3) ? '0.4' : '1';
        nextBtn.style.cursor = (page >= totalPages3) ? 'not-allowed' : 'pointer';
      }
      // 重置全选复选框
      var selectAllCb = document.getElementById('sig-select-all-cb');
      if (selectAllCb) selectAllCb.checked = false;
      var selectAllCbH = document.querySelector('.sig-select-all-cb-h');
      if (selectAllCbH) selectAllCbH.checked = false;
      var selectAllCbW = document.querySelector('.sig-select-all-cb-w');
      if (selectAllCbW) selectAllCbW.checked = false;

      updateSigViewerSelection();
      if (window.lucide) lucide.createIcons();
    }

    function buildSigRow(item, category) {
      var row = document.createElement('div');
      row.className = 'sigrow flex items-center';
      row.style.cssText = 'padding:10px 14px; border-bottom:1px solid var(--psls-border-soft); transition:background-color 0.15s;';
      row.addEventListener('mouseenter', function() { this.style.backgroundColor = 'var(--psls-background-soft)'; });
      row.addEventListener('mouseleave', function() { this.style.backgroundColor = ''; });

      var key, checkboxHtml, cellsHtml;
      if (category === 'malware') {
        key = item.hash || '';
        checkboxHtml = '<div style="width:36px; flex-shrink:0; display:flex; justify-content:center;">' +
          '<input type="checkbox" class="sig-row-cb" data-sig-key="' + escapeHtml(key) + '" style="width:15px; height:15px; accent-color: var(--psls-primary); cursor:pointer;"></div>';
        var name = item.name || '—';
        var mtype = item.type || '—';
        var severity = item.severity || 'medium';
        var sevClass = severity === 'high' ? 'badge-danger' : severity === 'medium' ? 'badge-warning' : 'badge-info';
        var sevText = severity === 'high' ? '高' : severity === 'medium' ? '中' : '低';
        var hashShort = (item.hash || '').length > 24 ? (item.hash || '').substring(0, 12) + '...' + (item.hash || '').substring((item.hash || '').length - 8) : (item.hash || '—');
        var source = item.source || '—';
        var added = (item.added_date || '').replace('T', ' ').substring(0, 19) || '—';
        cellsHtml =
          '<div style="width:22%; font-size:13px; color:var(--psls-foreground); padding:0 8px; font-weight:500; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(name) + '">' + escapeHtml(name) + '</div>' +
          '<div style="width:12%; font-size:12px; padding:0 8px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><span class="badge ' + sevClass + '">' + escapeHtml(mtype) + '</span></div>' +
          '<div style="width:10%; font-size:12px; padding:0 8px;"><span class="badge ' + sevClass + '">' + escapeHtml(sevText) + '</span></div>' +
          '<div style="width:24%; font-size:11px; padding:0 8px; font-family:var(--psls-font-mono); color:var(--psls-muted-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(item.hash || '') + '">' + escapeHtml(hashShort) + '</div>' +
          '<div style="width:10%; font-size:12px; padding:0 8px; color:var(--psls-muted-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(source) + '">' + escapeHtml(source) + '</div>' +
          '<div style="width:14%; font-size:12px; padding:0 8px; color:var(--psls-muted-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + escapeHtml(added) + '</div>';
      } else if (category === 'heuristic') {
        key = String(item.id || '');
        checkboxHtml = '<div style="width:36px; flex-shrink:0; display:flex; justify-content:center;">' +
          '<input type="checkbox" class="sig-row-cb" data-sig-key="' + escapeHtml(key) + '" style="width:15px; height:15px; accent-color: var(--psls-primary); cursor:pointer;"></div>';
        var ruleName = item.name || '—';
        var ruleType = item.rule_type || '—';
        var pattern = item.pattern || '';
        var patternShort = pattern.length > 60 ? pattern.substring(0, 50) + '...' + pattern.substring(pattern.length - 8) : pattern;
        var threshold = item.threshold || 1;
        var hsev = item.severity || 'medium';
        var hsevClass = hsev === 'high' ? 'badge-danger' : hsev === 'medium' ? 'badge-warning' : 'badge-info';
        var hsevText = hsev === 'high' ? '高' : hsev === 'medium' ? '中' : '低';
        var desc = item.description || '';
        var descShort = desc.length > 30 ? desc.substring(0, 28) + '...' : desc;
        cellsHtml =
          '<div style="width:20%; font-size:13px; color:var(--psls-foreground); padding:0 8px; font-weight:500; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(ruleName) + '">' + escapeHtml(ruleName) + '</div>' +
          '<div style="width:12%; font-size:12px; padding:0 8px;"><span class="badge badge-info">' + escapeHtml(ruleType) + '</span></div>' +
          '<div style="width:28%; font-size:11px; padding:0 8px; font-family:var(--psls-font-mono); color:var(--psls-muted-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(pattern) + '">' + escapeHtml(patternShort || '—') + '</div>' +
          '<div style="width:10%; font-size:12px; padding:0 8px; color:var(--psls-foreground); text-align:center;">' + escapeHtml(String(threshold)) + '</div>' +
          '<div style="width:10%; font-size:12px; padding:0 8px;"><span class="badge ' + hsevClass + '">' + escapeHtml(hsevText) + '</span></div>' +
          '<div style="width:16%; font-size:12px; padding:0 8px; color:var(--psls-muted-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(desc) + '">' + escapeHtml(descShort || '—') + '</div>';
      } else { // whitelist
        key = item.hash || '';
        checkboxHtml = '<div style="width:36px; flex-shrink:0; display:flex; justify-content:center;">' +
          '<input type="checkbox" class="sig-row-cb" data-sig-key="' + escapeHtml(key) + '" style="width:15px; height:15px; accent-color: var(--psls-primary); cursor:pointer;"></div>';
        var wlHash = item.hash || '';
        var wlHashShort = wlHash.length > 32 ? wlHash.substring(0, 16) + '...' + wlHash.substring(wlHash.length - 12) : wlHash;
        var wlReason = item.reason || '—';
        var wlAdded = (item.added_date || '').replace('T', ' ').substring(0, 19) || '—';
        cellsHtml =
          '<div style="width:50%; font-size:11px; padding:0 8px; font-family:var(--psls-font-mono); color:var(--psls-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(wlHash) + '">' + escapeHtml(wlHashShort) + '</div>' +
          '<div style="width:30%; font-size:12px; padding:0 8px; color:var(--psls-muted-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="' + escapeHtml(wlReason) + '">' + escapeHtml(wlReason) + '</div>' +
          '<div style="width:12%; font-size:12px; padding:0 8px; color:var(--psls-muted-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + escapeHtml(wlAdded) + '</div>';
      }

      // 操作列（行内删除按钮）
      var actionHtml =
        '<div style="width:8%; padding:0 8px; display:flex; justify-content:center; flex-shrink:0;">' +
          '<button class="sig-row-delete" title="删除" data-sig-row-action="delete" data-sig-key="' + escapeHtml(key) + '" style="width:26px; height:26px; border:1px solid var(--psls-border); background-color:var(--psls-card); border-radius:6px; display:flex; align-items:center; justify-content:center; color:var(--psls-danger); cursor:pointer;">' +
            '<i data-lucide="trash-2" style="width:13px;height:13px;"></i>' +
          '</button>' +
        '</div>';

      row.innerHTML = checkboxHtml + cellsHtml + actionHtml;
      row.setAttribute('data-sig-key', key);
      return row;
    }

    function updateSigViewerSelection() {
      var checkboxes = document.querySelectorAll('#sig-list .sig-row-cb');
      var selected = 0;
      checkboxes.forEach(function(cb) {
        if (cb.checked) {
          selected++;
          cb.closest('.sigrow').style.backgroundColor = 'var(--psls-c-cat-file-06)';
        } else {
          cb.closest('.sigrow').style.backgroundColor = '';
        }
      });
      // 选中信息
      var infoEl = document.getElementById('sig-selection-info');
      if (infoEl) infoEl.textContent = '已选 ' + selected + ' 项';
      // 批量删除按钮启用/禁用
      var batchBtn = document.querySelector('#page-tool-sigviewer [data-action="sig-delete-batch"]');
      if (batchBtn) {
        if (selected > 0) {
          batchBtn.disabled = false;
          batchBtn.style.opacity = '1';
          batchBtn.style.cursor = 'pointer';
        } else {
          batchBtn.disabled = true;
          batchBtn.style.opacity = '0.4';
          batchBtn.style.cursor = 'not-allowed';
        }
      }
      // 全选复选框状态
      var selectAllCb = null;
      if (sigViewerState.category === 'malware') {
        selectAllCb = document.getElementById('sig-select-all-cb');
      } else if (sigViewerState.category === 'heuristic') {
        selectAllCb = document.querySelector('.sig-select-all-cb-h');
      } else {
        selectAllCb = document.querySelector('.sig-select-all-cb-w');
      }
      if (selectAllCb) {
        selectAllCb.checked = checkboxes.length > 0 && selected === checkboxes.length;
      }
    }

    function executeSigBatchDelete() {
      var checkboxes = document.querySelectorAll('#sig-list .sig-row-cb:checked');
      if (checkboxes.length === 0) return;
      var keys = [];
      checkboxes.forEach(function(cb) {
        var k = cb.getAttribute('data-sig-key');
        if (k) keys.push(k);
      });
      if (keys.length === 0 || !pyBridge) return;
      // 二次确认
      if (!window.confirm('确定要删除选中的 ' + keys.length + ' 条记录吗？此操作不可撤销。')) return;
      try {
        pyBridge.deleteSignatureBatch(JSON.stringify(keys), sigViewerState.category);
      } catch(e) {
        console.error('deleteSignatureBatch 调用失败:', e);
      }
    }

    function executeSigSingleDelete(key) {
      if (!key || !pyBridge) return;
      if (!window.confirm('确定要删除此条记录吗？此操作不可撤销。')) return;
      try {
        pyBridge.deleteSignatureItem(String(key), sigViewerState.category);
      } catch(e) {
        console.error('deleteSignatureItem 调用失败:', e);
      }
    }

    function handleSignatureDeleteResult(data) {
      if (!data) return;
      if (data.success) {
        // 删除成功后刷新当前页
        var deletedCount = data.deleted || 1;
        // 如果是清空全部操作（clearedAll），重置回到第1页并弹出提示
        if (data.clearedAll) {
          sigViewerState.page = 1;
          var categoryNames = {malware: '恶意软件签名', heuristic: '启发式规则', whitelist: '白名单'};
          var catName = categoryNames[data.category] || data.category;
          showInfoToast('重置' + catName, '已清空 ' + deletedCount + ' 条记录', 'success', 3000);
        } else {
          // 如果当前页删除后为空且不是第一页，则回到上一页
          if (sigViewerState.page > 1) {
            var remaining = sigViewerState.total - deletedCount;
            var totalPages = Math.max(1, Math.ceil(remaining / sigViewerState.pageSize));
            if (sigViewerState.page > totalPages) {
              sigViewerState.page = totalPages;
            }
          }
        }
        loadSigViewerPage();
        // 同步签名计数徽章
        if (typeof data.count === 'number') {
          updateSignatureBadge(data.count);
        }
      } else {
        var errMsg = data.error || '删除失败';
        window.alert('删除失败: ' + errMsg);
      }
    }

    var _sigViewerPageInitialized = false;
    function initSigViewerPage() {
      if (_sigViewerPageInitialized) return;
      var page = document.getElementById('page-tool-sigviewer');
      if (!page) return;
      _sigViewerPageInitialized = true;

      // 标签页切换
      page.querySelectorAll('.sig-tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var cat = btn.getAttribute('data-sig-tab');
          if (cat && cat !== sigViewerState.category) switchSigTab(cat);
        });
      });

      // 搜索按钮
      var searchBtn = page.querySelector('[data-action="sig-search"]');
      if (searchBtn) {
        searchBtn.addEventListener('click', function() {
          var input = document.getElementById('sig-search-input');
          sigViewerState.search = (input ? input.value : '').trim();
          sigViewerState.page = 1;
          sigViewerState.selectedKeys.clear();
          loadSigViewerPage();
        });
      }
      // 搜索框回车
      var searchInput = document.getElementById('sig-search-input');
      if (searchInput) {
        searchInput.addEventListener('keydown', function(e) {
          if (e.key === 'Enter') {
            sigViewerState.search = this.value.trim();
            sigViewerState.page = 1;
            sigViewerState.selectedKeys.clear();
            loadSigViewerPage();
          }
        });
      }

      // 全选按钮（工具栏）
      var selectAllBtn = page.querySelector('[data-action="sig-select-all"]');
      if (selectAllBtn) {
        selectAllBtn.addEventListener('click', function() {
          var checkboxes = document.querySelectorAll('#sig-list .sig-row-cb');
          if (checkboxes.length === 0) return;
          var allChecked = true;
          checkboxes.forEach(function(cb) { if (!cb.checked) allChecked = false; });
          checkboxes.forEach(function(cb) { cb.checked = !allChecked; });
          // 同步表头全选
          var selectAllCb = null;
          if (sigViewerState.category === 'malware') selectAllCb = document.getElementById('sig-select-all-cb');
          else if (sigViewerState.category === 'heuristic') selectAllCb = document.querySelector('.sig-select-all-cb-h');
          else selectAllCb = document.querySelector('.sig-select-all-cb-w');
          if (selectAllCb) selectAllCb.checked = !allChecked;
          updateSigViewerSelection();
        });
      }

      // 表头全选复选框（malware / heuristic / whitelist）
      var selectAllCbMalware = document.getElementById('sig-select-all-cb');
      if (selectAllCbMalware) {
        selectAllCbMalware.addEventListener('change', function() {
          var checked = this.checked;
          document.querySelectorAll('#sig-list .sig-row-cb').forEach(function(cb) { cb.checked = checked; });
          updateSigViewerSelection();
        });
      }
      var selectAllCbH = document.querySelector('.sig-select-all-cb-h');
      if (selectAllCbH) {
        selectAllCbH.addEventListener('change', function() {
          var checked = this.checked;
          document.querySelectorAll('#sig-list .sig-row-cb').forEach(function(cb) { cb.checked = checked; });
          updateSigViewerSelection();
        });
      }
      var selectAllCbW = document.querySelector('.sig-select-all-cb-w');
      if (selectAllCbW) {
        selectAllCbW.addEventListener('change', function() {
          var checked = this.checked;
          document.querySelectorAll('#sig-list .sig-row-cb').forEach(function(cb) { cb.checked = checked; });
          updateSigViewerSelection();
        });
      }

      // 批量删除按钮
      var batchDeleteBtn = page.querySelector('[data-action="sig-delete-batch"]');
      if (batchDeleteBtn) {
        batchDeleteBtn.addEventListener('click', function() {
          if (this.disabled) return;
          executeSigBatchDelete();
        });
      }

      // 重置白名单按钮
      var clearWlBtn = document.getElementById('sig-clear-whitelist-btn');
      if (clearWlBtn) {
        clearWlBtn.addEventListener('click', function() {
          if (!pyBridge) {
            showInfoToast('重置白名单', '后端桥接未就绪', 'warning', 2500);
            return;
          }
          if (!window.confirm('此操作将删除所有白名单条目，不可恢复。确定要重置白名单吗？')) {
            return;
          }
          try {
            pyBridge.clearAllSignaturesByCategory('whitelist');
          } catch(e) {
            console.error('clearAllSignaturesByCategory 调用失败:', e);
            showInfoToast('重置白名单', '调用失败: ' + e.message, 'danger', 3500);
          }
        });
      }

      // 翻页按钮
      var prevPageBtn = page.querySelector('[data-action="sig-prev-page"]');
      if (prevPageBtn) {
        prevPageBtn.addEventListener('click', function() {
          if (this.disabled || sigViewerState.page <= 1) return;
          sigViewerState.page--;
          sigViewerState.selectedKeys.clear();
          loadSigViewerPage();
        });
      }
      var nextPageBtn = page.querySelector('[data-action="sig-next-page"]');
      if (nextPageBtn) {
        nextPageBtn.addEventListener('click', function() {
          if (this.disabled) return;
          var totalPages = Math.max(1, Math.ceil(sigViewerState.total / sigViewerState.pageSize));
          if (sigViewerState.page >= totalPages) return;
          sigViewerState.page++;
          sigViewerState.selectedKeys.clear();
          loadSigViewerPage();
        });
      }

      // 列表事件委托（行内删除按钮 + 复选框变化）
      var listEl = document.getElementById('sig-list');
      if (listEl) {
        listEl.addEventListener('click', function(e) {
          var btn = e.target.closest('[data-sig-row-action]');
          if (!btn) return;
          var action = btn.getAttribute('data-sig-row-action');
          var key = btn.getAttribute('data-sig-key');
          if (action === 'delete' && key) {
            executeSigSingleDelete(key);
          }
        });
        listEl.addEventListener('change', function(e) {
          if (e.target.classList && e.target.classList.contains('sig-row-cb')) {
            updateSigViewerSelection();
          }
        });
      }
    }

    // ========================================================================
    // ===== 子页面 3：PE 文件分析 =====
    // ========================================================================
    function resetPEAnalysis() {
      var pathInput = document.getElementById('pe-file-path');
      if (pathInput) pathInput.value = '';
      var emptyState = document.getElementById('pe-empty-state');
      var grid = document.getElementById('pe-analysis-grid');
      var packerRow = document.getElementById('pe-packer-row');
      if (emptyState) emptyState.style.display = '';
      if (grid) grid.classList.add('hidden');
      if (packerRow) packerRow.innerHTML = '<span style="font-size:12px; color:var(--psls-muted-foreground);">尚未选择文件</span>';
    }

    function renderPEAnalysis(data) {
      var emptyState = document.getElementById('pe-empty-state');
      var grid = document.getElementById('pe-analysis-grid');
      if (data.error) {
        if (emptyState) {
          emptyState.style.display = '';
          emptyState.innerHTML =
            '<div class="flex items-center justify-center mb-4" style="width:72px; height:72px; border-radius:50%; background-color:var(--psls-c-danger-10);">' +
              '<i data-lucide="alert-triangle" style="width:36px;height:36px; color:var(--psls-danger);"></i>' +
            '</div>' +
            '<div style="font-size:16px; font-weight:600; color:var(--psls-foreground); margin-bottom:6px;">分析失败</div>' +
            '<div style="font-size:13px; color:var(--psls-danger);">' + escapeHtml(data.error) + '</div>';
        }
        if (grid) grid.classList.add('hidden');
        if (window.lucide) lucide.createIcons();
        return;
      }
      if (emptyState) emptyState.style.display = 'none';
      if (grid) grid.classList.remove('hidden');
      // 基本信息
      var basicEl = document.getElementById('pe-basic-info');
      if (basicEl && data.basic) {
        var b = data.basic;
        basicEl.innerHTML =
          '<div class="flex justify-between"><span style="font-size:12px;color:var(--psls-muted-foreground);">文件名</span><span style="font-size:12px;font-weight:500;text-align:right;word-break:break-all;">' + escapeHtml(b.filename || '—') + '</span></div>' +
          '<div class="flex justify-between"><span style="font-size:12px;color:var(--psls-muted-foreground);">文件大小</span><span style="font-size:12px;font-weight:500;">' + formatFileSize(b.size) + '</span></div>' +
          '<div class="flex justify-between"><span style="font-size:12px;color:var(--psls-muted-foreground);">编译时间</span><span style="font-size:12px;font-weight:500;">' + escapeHtml(b.compile_time || '—') + '</span></div>' +
          '<div class="flex justify-between"><span style="font-size:12px;color:var(--psls-muted-foreground);">MD5</span><span style="font-size:11px;font-weight:500;font-family:var(--psls-font-mono);word-break:break-all;text-align:right;">' + escapeHtml(b.md5 || '—') + '</span></div>' +
          '<div class="flex justify-between"><span style="font-size:12px;color:var(--psls-muted-foreground);">SHA256</span><span style="font-size:11px;font-weight:500;font-family:var(--psls-font-mono);word-break:break-all;text-align:right;">' + escapeHtml(b.sha256 || '—') + '</span></div>';
      }
      // 风险评分
      var riskEl = document.getElementById('pe-risk-score');
      if (riskEl) {
        var score = data.risk_score || 0;
        var riskColor = score >= 70 ? 'var(--psls-danger)' : score >= 40 ? 'var(--psls-warning)' : 'var(--psls-success)';
        var riskLabel = score >= 70 ? '高风险' : score >= 40 ? '中等风险' : '低风险';
        riskEl.innerHTML =
          '<div class="flex items-center gap-3">' +
            '<div style="width:64px;height:64px;border-radius:50%;border:4px solid ' + riskColor + ';display:flex;align-items:center;justify-content:center;">' +
              '<span style="font-size:20px;font-weight:700;color:' + riskColor + ';">' + score + '</span>' +
            '</div>' +
            '<div><div style="font-size:14px;font-weight:600;color:' + riskColor + ';">' + riskLabel + '</div><div style="font-size:11px;color:var(--psls-muted-foreground);">评分范围 0-100</div></div>' +
          '</div>';
      }
      // 打包器检测
      var packerRow = document.getElementById('pe-packer-row');
      if (packerRow) {
        var packer = data.packer || {};
        if (packer.detected) {
          packerRow.innerHTML = '<span class="badge badge-warning" style="font-size:12px;padding:4px 10px;">检测到打包器: ' + escapeHtml(packer.name || '未知') + '</span>';
        } else {
          packerRow.innerHTML = '<span class="badge badge-safe" style="font-size:12px;padding:4px 10px;">未检测到打包器</span>';
        }
      }
      // 节区信息
      var sectionsBody = document.getElementById('pe-sections-body');
      var sectionCount = document.getElementById('pe-section-count');
      var sections = data.sections || [];
      if (sectionCount) sectionCount.textContent = '共 ' + sections.length + ' 个节区';
      if (sectionsBody) {
        sectionsBody.innerHTML = sections.map(function(s) {
          var entropy = s.entropy || 0;
          var entropyColor = entropy > 7.0 ? 'var(--psls-danger)' : entropy > 6.0 ? 'var(--psls-warning)' : 'var(--psls-foreground)';
          var features = [];
          if (entropy > 7.0) features.push('<span style="color:var(--psls-danger);">高熵</span>');
          if (s.raw_size === 0) features.push('<span style="color:var(--psls-warning);">无原始数据</span>');
          return '<tr>' +
            '<td style="font-family:var(--psls-font-mono);font-weight:500;">' + escapeHtml(s.name || '—') + '</td>' +
            '<td style="text-align:right;font-family:var(--psls-font-mono);">0x' + (s.vaddr || 0).toString(16).toUpperCase() + '</td>' +
            '<td style="text-align:right;font-family:var(--psls-font-mono);">' + (s.vsize || 0).toLocaleString() + '</td>' +
            '<td style="text-align:right;font-family:var(--psls-font-mono);">' + (s.raw_size || 0).toLocaleString() + '</td>' +
            '<td style="text-align:right;font-family:var(--psls-font-mono);color:' + entropyColor + ';">' + entropy.toFixed(4) + '</td>' +
            '<td>' + (features.length ? features.join(' / ') : '—') + '</td>' +
          '</tr>';
        }).join('');
      }
      // 导入表
      var importsBody = document.getElementById('pe-imports-body');
      var importCount = document.getElementById('pe-import-count');
      var imports = data.imports || [];
      var totalFuncs = 0;
      imports.forEach(function(imp) { totalFuncs += (imp.functions || []).length; });
      if (importCount) importCount.textContent = imports.length + ' 个 DLL / ' + totalFuncs + ' 个函数';
      if (importsBody) {
        importsBody.innerHTML = imports.map(function(imp) {
          var funcs = (imp.functions || []).map(function(f) {
            return '<span style="display:inline-block;font-size:11px;font-family:var(--psls-font-mono);padding:2px 6px;margin:2px;background-color:var(--psls-background-soft);border-radius:4px;">' + escapeHtml(f) + '</span>';
          }).join('');
          return '<div>' +
            '<div style="font-size:12px;font-weight:600;color:var(--psls-primary);margin-bottom:4px;font-family:var(--psls-font-mono);">' + escapeHtml(imp.dll || '—') + '</div>' +
            '<div style="display:flex;flex-wrap:wrap;gap:2px;">' + funcs + '</div>' +
          '</div>';
        }).join('');
      }
      if (window.lucide) lucide.createIcons();
    }

    var _pePageInitialized = false;
    function initPEPage() {
      if (_pePageInitialized) return;
      var page = document.getElementById('page-tool-pe');
      if (!page) return;
      _pePageInitialized = true;
      var selectBtn = page.querySelector('[data-action="select-pe-file"]');
      if (selectBtn) selectBtn.addEventListener('click', function() {
        if (pyBridge) pyBridge.selectSingleFile('pe');
      });
    }

    // ========================================================================
    // ===== 子页面 3.5：沙箱分析 =====
    // ========================================================================
    var _sandboxPageInitialized = false;
    var _sandboxAnalyzing = false;

    function initSandboxPage() {
      if (_sandboxPageInitialized) return;
      var page = document.getElementById('page-tool-sandbox');
      if (!page) return;
      _sandboxPageInitialized = true;
      var selectBtn = page.querySelector('[data-action="select-sandbox-file"]');
      if (selectBtn) selectBtn.addEventListener('click', function() {
        if (pyBridge) pyBridge.selectSingleFile('sandbox');
      });
      var startBtn = document.getElementById('sandbox-start-btn');
      if (startBtn) startBtn.addEventListener('click', function() {
        if (_sandboxAnalyzing) return;
        var pathInput = document.getElementById('sandbox-file-path');
        var filePath = pathInput ? pathInput.value : '';
        if (!filePath) return;
        if (pyBridge && pyBridge.analyzeInSandbox) {
          _sandboxAnalyzing = true;
          startBtn.disabled = true;
          startBtn.style.opacity = '0.5';
          pyBridge.analyzeInSandbox(filePath);
          // 显示进度区
          var progressArea = document.getElementById('sandbox-progress-area');
          if (progressArea) progressArea.style.display = '';
          var stageEl = document.getElementById('sandbox-progress-stage');
          if (stageEl) stageEl.textContent = '正在准备...';
          var barEl = document.getElementById('sandbox-progress-bar');
          if (barEl) barEl.style.width = '0%';
          // 隐藏旧结果
          var emptyState = document.getElementById('sandbox-empty-state');
          var resultContent = document.getElementById('sandbox-result-content');
          if (emptyState) emptyState.style.display = '';
          if (resultContent) resultContent.classList.add('hidden');
        }
      });
    }

    function resetSandboxAnalysis() {
      var pathInput = document.getElementById('sandbox-file-path');
      if (pathInput) pathInput.value = '';
      var startBtn = document.getElementById('sandbox-start-btn');
      if (startBtn) startBtn.style.display = 'none';
      var progressArea = document.getElementById('sandbox-progress-area');
      if (progressArea) progressArea.style.display = 'none';
      var emptyState = document.getElementById('sandbox-empty-state');
      var resultContent = document.getElementById('sandbox-result-content');
      if (emptyState) emptyState.style.display = '';
      if (resultContent) resultContent.classList.add('hidden');
      _sandboxAnalyzing = false;
    }

    function updateSandboxProgress(data) {
      var stageEl = document.getElementById('sandbox-progress-stage');
      var barEl = document.getElementById('sandbox-progress-bar');
      if (stageEl && data.stage) stageEl.textContent = data.stage;
      if (barEl && typeof data.percent === 'number') {
        barEl.style.width = Math.min(100, data.percent) + '%';
      }
    }

    function renderSandboxResult(data) {
      _sandboxAnalyzing = false;
      var startBtn = document.getElementById('sandbox-start-btn');
      if (startBtn) { startBtn.disabled = false; startBtn.style.opacity = '1'; }

      // 隐藏进度区
      var progressArea = document.getElementById('sandbox-progress-area');
      if (progressArea) progressArea.style.display = 'none';

      var emptyState = document.getElementById('sandbox-empty-state');
      var resultContent = document.getElementById('sandbox-result-content');
      if (emptyState) emptyState.style.display = 'none';
      if (resultContent) resultContent.classList.remove('hidden');

      // 错误处理
      if (data.error) {
        var verdictText = document.getElementById('sandbox-verdict-text');
        var verdictCard = document.getElementById('sandbox-verdict-card');
        if (verdictText) { verdictText.textContent = '错误'; verdictText.style.color = 'var(--psls-muted-foreground)'; }
        if (verdictCard) verdictCard.style.backgroundColor = 'var(--psls-background-soft)';
        var scoreEl = document.getElementById('sandbox-score-text');
        if (scoreEl) scoreEl.innerHTML = '0<span style="font-size:14px; color:var(--psls-muted-foreground);">/100</span>';
        var durEl = document.getElementById('sandbox-duration-text');
        if (durEl) durEl.innerHTML = (data.duration || 0).toFixed(1) + '<span style="font-size:14px; color:var(--psls-muted-foreground);">s</span>';
        var timelineEl = document.getElementById('sandbox-behavior-timeline');
        if (timelineEl) timelineEl.innerHTML = '<div style="text-align:center; padding:24px; color:var(--psls-muted-foreground); font-size:13px;">' + data.error + '</div>';
        if (window.lucide) lucide.createIcons();
        return;
      }

      // 判定结果
      var verdict = data.verdict || 'clean';
      var verdictText = document.getElementById('sandbox-verdict-text');
      var verdictCard = document.getElementById('sandbox-verdict-card');
      var verdictLabels = { 'malware': '恶意', 'suspicious': '可疑', 'clean': '安全', 'error': '错误', 'skipped': '跳过（过大）' };
      var verdictColors = { 'malware': 'var(--psls-c-cat-process)', 'suspicious': 'var(--psls-c-warn-alt)', 'clean': 'var(--psls-c-success-dot)', 'error': 'var(--psls-muted-foreground)' };
      var verdictBgs = { 'malware': 'var(--psls-c-cat-process-08)', 'suspicious': 'var(--psls-c-warn-08)', 'clean': 'var(--psls-c-success-08)', 'error': 'var(--psls-background-soft)' };
      if (verdictText) { verdictText.textContent = verdictLabels[verdict] || verdict; verdictText.style.color = verdictColors[verdict] || 'var(--psls-foreground)'; }
      if (verdictCard) verdictCard.style.backgroundColor = verdictBgs[verdict] || 'var(--psls-background-soft)';

      // 评分
      var scoreEl = document.getElementById('sandbox-score-text');
      if (scoreEl) scoreEl.innerHTML = (data.score || 0) + '<span style="font-size:14px; color:var(--psls-muted-foreground);">/100</span>';

      // 耗时
      var durEl = document.getElementById('sandbox-duration-text');
      if (durEl) durEl.innerHTML = (data.duration || 0).toFixed(1) + '<span style="font-size:14px; color:var(--psls-muted-foreground);">s</span>';

      // 引擎信息
      var engineEl = document.getElementById('sandbox-engine-text');
      if (engineEl) engineEl.textContent = data.frida_used ? 'psutil + frida' : 'psutil';

      // 行为数量
      var behaviors = data.behaviors || [];
      var behaviorCountEl = document.getElementById('sandbox-behavior-count');
      if (behaviorCountEl) behaviorCountEl.textContent = behaviors.length + ' 条';

      // 分类评分
      var categoryLabels = { 'file': '文件操作', 'registry': '注册表', 'network': '网络活动', 'process': '进程操作', 'system': '系统修改', 'anti_analysis': '反分析' };
      var categoryMax = { 'file': 20, 'registry': 15, 'network': 15, 'process': 20, 'system': 15, 'anti_analysis': 15 };
      var categoryColors = { 'file': 'var(--psls-c-cat-file)', 'registry': 'var(--psls-c-cat-registry)', 'network': 'var(--psls-c-accent-glow)', 'process': 'var(--psls-c-cat-process)', 'system': 'var(--psls-c-warn-alt)', 'anti_analysis': 'var(--psls-c-cat-anti)' };
      var categoryScores = {};
      behaviors.forEach(function(b) {
        if (categoryScores[b.category] === undefined) categoryScores[b.category] = 0;
        categoryScores[b.category] += (b.score || 0);
      });
      var catContainer = document.getElementById('sandbox-category-scores');
      if (catContainer) {
        catContainer.innerHTML = '';
        Object.keys(categoryMax).forEach(function(cat) {
          var raw = categoryScores[cat] || 0;
          var capped = Math.min(raw, categoryMax[cat]);
          var percent = (capped / categoryMax[cat]) * 100;
          var color = categoryColors[cat] || 'var(--psls-primary)';
          var row = document.createElement('div');
          row.style.cssText = 'display:flex; align-items:center; gap:10px;';
          row.innerHTML =
            '<span style="font-size:12px; color:var(--psls-foreground); width:80px; flex-shrink:0;">' + (categoryLabels[cat] || cat) + '</span>' +
            '<div style="flex:1; height:8px; background-color:var(--psls-background-soft); border-radius:4px; overflow:hidden;">' +
              '<div style="width:' + percent + '%; height:100%; background-color:' + color + '; border-radius:4px; transition:width 0.5s ease;"></div>' +
            '</div>' +
            '<span style="font-size:12px; font-weight:600; color:' + color + '; width:50px; text-align:right; flex-shrink:0;">' + capped + '/' + categoryMax[cat] + '</span>';
          catContainer.appendChild(row);
        });
      }

      // 行为时间线
      var timelineEl = document.getElementById('sandbox-behavior-timeline');
      var timelineCountEl = document.getElementById('sandbox-timeline-count');
      if (timelineCountEl) timelineCountEl.textContent = behaviors.length + ' 条记录';
      if (timelineEl) {
        timelineEl.innerHTML = '';
        if (behaviors.length === 0) {
          timelineEl.innerHTML = '<div style="text-align:center; padding:24px; color:var(--psls-muted-foreground); font-size:13px;">未检测到可疑行为</div>';
        } else {
          var severityIcons = { 'critical': 'alert-circle', 'warn': 'alert-triangle', 'info': 'info' };
          var severityColors = { 'critical': 'var(--psls-c-cat-process)', 'warn': 'var(--psls-c-warn-alt)', 'info': 'var(--psls-muted-foreground)' };
          behaviors.forEach(function(b) {
            var item = document.createElement('div');
            item.style.cssText = 'display:flex; align-items:flex-start; gap:8px; padding:8px 10px; border-radius:6px; background-color:var(--psls-background-soft);';
            var sev = b.severity || 'info';
            var sevColor = severityColors[sev] || 'var(--psls-muted-foreground)';
            var sevIcon = severityIcons[sev] || 'info';
            var catLabel = categoryLabels[b.category] || b.category;
            item.innerHTML =
              '<i data-lucide="' + sevIcon + '" style="width:16px; height:16px; color:' + sevColor + '; flex-shrink:0; margin-top:1px;"></i>' +
              '<div style="flex:1; min-width:0;">' +
                '<div style="display:flex; align-items:center; gap:6px; margin-bottom:2px;">' +
                  '<span style="font-size:11px; padding:1px 6px; border-radius:4px; background-color:' + sevColor + '20; color:' + sevColor + '; font-weight:500;">' + catLabel + '</span>' +
                  '<span style="font-size:12px; font-weight:500; color:var(--psls-foreground);">' + (b.description || '') + '</span>' +
                '</div>' +
                (b.detail ? '<div style="font-size:11px; color:var(--psls-muted-foreground); font-family:var(--psls-font-mono);">' + b.detail + '</div>' : '') +
              '</div>' +
              '<span style="font-size:11px; color:var(--psls-muted-foreground); flex-shrink:0;">+' + (b.score || 0) + '</span>';
            timelineEl.appendChild(item);
          });
        }
      }

      if (window.lucide) lucide.createIcons();
    }

    // ========================================================================
    // ===== 子页面 4：哈希计算 =====
    // ========================================================================
    function resetHashCalculator() {
      var pathInput = document.getElementById('hash-file-path');
      if (pathInput) pathInput.value = '';
      var emptyState = document.getElementById('hash-empty-state');
      var container = document.getElementById('hash-results-container');
      if (emptyState) emptyState.style.display = '';
      if (container) container.style.display = 'none';
      ['hash-md5', 'hash-sha1', 'hash-sha256'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.value = '';
      });
      ['info-filename', 'info-filesize', 'info-modtime'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.textContent = '—';
      });
    }

    function renderHashResult(data) {
      var emptyState = document.getElementById('hash-empty-state');
      var container = document.getElementById('hash-results-container');
      if (data.error) {
        if (emptyState) emptyState.style.display = '';
        if (container) container.style.display = 'none';
        if (window.lucide) lucide.createIcons();
        return;
      }
      if (emptyState) emptyState.style.display = 'none';
      if (container) container.style.display = '';
      var md5El = document.getElementById('hash-md5');
      var sha1El = document.getElementById('hash-sha1');
      var sha256El = document.getElementById('hash-sha256');
      if (md5El) md5El.value = data.md5 || '';
      if (sha1El) sha1El.value = data.sha1 || '';
      if (sha256El) sha256El.value = data.sha256 || '';
      var nameEl = document.getElementById('info-filename');
      var sizeEl = document.getElementById('info-filesize');
      var timeEl = document.getElementById('info-modtime');
      if (nameEl) nameEl.textContent = data.filename || '—';
      if (sizeEl) sizeEl.textContent = formatFileSize(data.size);
      if (timeEl) timeEl.textContent = data.mtime || '—';
    }

    var _hashPageInitialized = false;
    function initHashPage() {
      if (_hashPageInitialized) return;
      // 哈希计算已并入 PE 分析页，选择/复制按钮均位于 page-tool-pe 内
      var page = document.getElementById('page-tool-pe');
      if (!page) return;
      _hashPageInitialized = true;
      var selectBtn = page.querySelector('[data-action="select-hash-file"]');
      if (selectBtn) selectBtn.addEventListener('click', function() {
        if (pyBridge) pyBridge.selectSingleFile('hash');
      });
      // 复制按钮
      page.querySelectorAll('.hash-copy-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var targetId = btn.getAttribute('data-copy-target');
          var input = targetId ? document.getElementById(targetId) : null;
          if (!input || !input.value) return;
          try {
            input.select();
            document.execCommand('copy');
            var label = btn.querySelector('.copy-label');
            if (label) {
              var original = label.textContent;
              label.textContent = '已复制';
              setTimeout(function() { label.textContent = original; }, 1500);
            }
          } catch(e) { console.error('复制失败:', e); }
        });
      });
    }

    // ========================================================================
    // ===== 子页面 5：日志查看 =====
    // ========================================================================
    function loadLogs() {
      var levelEl = document.getElementById('logs-filter-level');
      var sourceEl = document.getElementById('logs-filter-source');
      var searchEl = document.getElementById('logs-search-input');
      var level = levelEl ? levelEl.value : 'ALL';
      var source = sourceEl ? sourceEl.value : 'ALL';
      var search = searchEl ? searchEl.value.trim() : '';
      if (pyBridge) pyBridge.getLogs(level, source, search);
    }

    function renderLogs(data) {
      var body = document.getElementById('log-table-body');
      if (!body) return;
      var items = (data && data.items) || [];
      var stats = (data && data.stats) || {};
      if (items.length === 0) {
        body.innerHTML = '<div style="padding:40px 20px;text-align:center;color:var(--psls-muted-foreground);font-size:13px;">暂无日志记录</div>';
      } else {
        // 分级获取等级颜色，同时统一 WARN/WARNING 展示为 WARN
        function _levelInfo(lv) {
          var u = (lv || '').toUpperCase();
          if (u === 'ERROR') return { tag: 'ERROR', color: 'var(--psls-danger)' };
          if (u === 'WARNING' || u === 'WARN') return { tag: 'WARN', color: 'var(--psls-warning)' };
          if (u === 'DEBUG') return { tag: 'DEBUG', color: 'var(--psls-muted-foreground)' };
          return { tag: u || 'INFO', color: 'var(--psls-info)' };
        }
        var htmlChunks = [];
        for (var i = 0; i < items.length; i++) {
          var item = items[i];
          if (!item) continue;
          var li = _levelInfo(item.level);
          htmlChunks.push('<div class="grid items-center" style="grid-template-columns: 160px 90px 110px 1fr; padding:8px 14px; border-bottom:1px solid var(--psls-border-soft); font-size:12px;">' +
            '<div style="color:var(--psls-muted-foreground);">' + escapeHtml(item.timestamp || '') + '</div>' +
            '<div><span style="padding:1px 6px;border-radius:3px;background-color:' + li.color + '20;color:' + li.color + ';font-weight:600;font-size:10px;">' + escapeHtml(li.tag) + '</span></div>' +
            '<div style="color:var(--psls-muted-foreground);">' + escapeHtml(item.source || '') + '</div>' +
            '<div style="color:var(--psls-foreground);word-break:break-word;">' + escapeHtml(item.message || '') + '</div>' +
          '</div>');
        }
        var notice = '';
        if (stats && typeof stats.total_matched === 'number' && stats.total_matched > items.length) {
          notice = '<div style="padding:10px 14px;font-size:11px;color:var(--psls-warning);border-bottom:1px solid var(--psls-border-soft);">' +
            '匹配到 ' + stats.total_matched.toLocaleString() + ' 条，仅显示最新 ' + items.length.toLocaleString() + ' 条（避免卡顿）</div>';
        }
        body.innerHTML = notice + htmlChunks.join('');
      }
      // 更新统计
      var statTotal = document.getElementById('stat-total');
      var statInfo = document.getElementById('stat-info');
      var statWarn = document.getElementById('stat-warn');
      var statError = document.getElementById('stat-error');
      if (statTotal) statTotal.textContent = (stats.total || 0).toLocaleString();
      if (statInfo) statInfo.textContent = (stats.info || 0).toLocaleString();
      if (statWarn) statWarn.textContent = (stats.warning || 0).toLocaleString();
      if (statError) statError.textContent = (stats.error || 0).toLocaleString();
      // 更新时间
      var lastUpdated = document.getElementById('logs-last-updated');
      if (lastUpdated) {
        var now = new Date();
        lastUpdated.textContent = '最后更新: ' +
          String(now.getHours()).padStart(2, '0') + ':' +
          String(now.getMinutes()).padStart(2, '0') + ':' +
          String(now.getSeconds()).padStart(2, '0');
      }
    }

    function onLogsExported(success) {
      if (success) {
        appendSigLog('日志导出成功', 'success');
      } else {
        appendSigLog('日志导出失败', 'error');
      }
      // 简单提示
      var toast = document.createElement('div');
      toast.style.cssText = 'position:fixed;bottom:20px;right:20px;padding:12px 20px;border-radius:8px;background-color:' + (success ? 'var(--psls-success)' : 'var(--psls-danger)') + ';color:#fff;font-size:13px;font-weight:500;z-index:9999;box-shadow:0 4px 12px rgba(0,0,0,0.15);';
      toast.textContent = success ? '日志导出成功' : '日志导出失败';
      document.body.appendChild(toast);
      setTimeout(function() { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 3000);
    }

    var _logsPageInitialized = false;
    function initLogsPage() {
      if (_logsPageInitialized) return;
      var page = document.getElementById('page-tool-logs');
      if (!page) return;
      _logsPageInitialized = true;
      var refreshBtn = page.querySelector('[data-action="refresh-logs"]');
      if (refreshBtn) refreshBtn.addEventListener('click', loadLogs);
      var exportBtn = page.querySelector('[data-action="export-logs"]');
      if (exportBtn) exportBtn.addEventListener('click', function() {
        var defaultName = 'PSLS_logs_' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '.txt';
        var savePath = window.prompt('请输入导出文件保存路径：', defaultName);
        if (savePath && pyBridge) pyBridge.exportLogs(savePath);
      });
      // 过滤器变化自动刷新
      var levelFilter = document.getElementById('logs-filter-level');
      if (levelFilter) levelFilter.addEventListener('change', loadLogs);
      var sourceFilter = document.getElementById('logs-filter-source');
      if (sourceFilter) sourceFilter.addEventListener('change', loadLogs);
      var searchInput = document.getElementById('logs-search-input');
      if (searchInput) {
        var searchTimer = null;
        searchInput.addEventListener('input', function() {
          if (searchTimer) clearTimeout(searchTimer);
          searchTimer = setTimeout(loadLogs, 400);
        });
      }
    }

    // ========================================================================
    // ===== 工具子页面统一初始化 =====
    // ========================================================================
    function initToolSubpages() {
      // 返回工具箱按钮（所有子页面共用）
      document.querySelectorAll('[data-action="back-to-tools"]').forEach(function(btn) {
        btn.addEventListener('click', function() { navigateTo('tools'); });
      });
      initQuarantinePage();
      initSignaturesPage();
      initSigViewerPage();
      initPEPage();
      initSandboxPage();
      initHashPage();
      initLogsPage();
      initMBPage();
    }

    // ===== Tool buttons =====
    // 工具卡片点击直接导航至对应子页面（按钮内嵌的快捷操作仍然保留）
    function initToolButtons() {
      var cardPageMap = {
        'tool-quarantine': 'tool-quarantine',
        'tool-signatures': 'tool-signatures',
        'tool-sigviewer': 'tool-sigviewer',
        'tool-pe': 'tool-pe',
        'tool-sandbox': 'tool-sandbox',
        'tool-logs': 'tool-logs',
        'tool-rollback': 'tool-rollback',
        'tool-mb': 'tool-mb'
      };
      Object.keys(cardPageMap).forEach(function(cardId) {
        var card = document.getElementById(cardId);
        if (!card) return;
        // 整张卡片点击 → 进入子页面
        card.addEventListener('click', function(e) {
          // 若点击源是卡片内的按钮，则交由按钮自身处理器处理（保留快捷入口）
          if (e.target.closest('button')) return;
          navigateTo(cardPageMap[cardId]);
        });
      });
      // 卡片内"打开"按钮 → 同样进入子页面（保持与卡片一致的行为）
      [
        { id: 'tool-quarantine', page: 'tool-quarantine' },
        { id: 'tool-signatures', page: 'tool-signatures' },
        { id: 'tool-sigviewer', page: 'tool-sigviewer' },
        { id: 'tool-pe', page: 'tool-pe' },
        { id: 'tool-sandbox', page: 'tool-sandbox' },
        { id: 'tool-logs', page: 'tool-logs' },
        { id: 'tool-rollback', page: 'tool-rollback' },
        { id: 'tool-mb', page: 'tool-mb' }
      ].forEach(function(item) {
        var btn = document.querySelector('#' + item.id + ' button');
        if (btn) btn.addEventListener('click', function(e) {
          e.stopPropagation();
          navigateTo(item.page);
        });
      });
    }

    // ===== Scan page buttons =====
    function initScanButtons() {
      var quickBtn = document.getElementById('btn-quick-scan');
      if (quickBtn) quickBtn.addEventListener('click', startQuickScan);
      var customBtn = document.getElementById('btn-custom-scan');
      if (customBtn) customBtn.addEventListener('click', startCustomScan);
      var stopBtn = document.getElementById('btn-stop-scan');
      if (stopBtn) stopBtn.addEventListener('click', stopScan);
      var browseFolderBtn = document.getElementById('btn-browse-folder');
      if (browseFolderBtn) browseFolderBtn.addEventListener('click', function() {
        if (pyBridge) {
          pyBridge.setBrowseTarget('scan-path');
          pyBridge.browseFolder();
        }
      });
      var browseFileBtn = document.getElementById('btn-browse-file');
      if (browseFileBtn) browseFileBtn.addEventListener('click', function() {
        if (pyBridge) {
          pyBridge.setBrowseTarget('scan-path');
          pyBridge.browseFile();
        }
      });
      var filter = document.getElementById('scan-result-filter');
      if (filter) filter.addEventListener('change', function() {
        var tbody = document.getElementById('scan-result-tbody');
        if (!tbody) return;
        var rows = tbody.querySelectorAll('tr');
        rows.forEach(function(row) {
          // 基于 data-status 属性筛选（恶意/可疑/安全/警告 独立分类）
          var statusKey = row.getAttribute('data-status') || 'safe';
          if (filter.value === 'all' || filter.value === statusKey) row.style.display = '';
          else row.style.display = 'none';
        });
      });

      // 扫描所有文件 <-> 仅扫描可执行文件 互斥逻辑
      var scanAllInput = document.getElementById('opt-scan-all');
      var exeOnlyInput = document.getElementById('opt-exe-only');
      if (scanAllInput) {
        scanAllInput.addEventListener('change', function() {
          if (scanAllInput.checked && exeOnlyInput && exeOnlyInput.checked) {
            exeOnlyInput.checked = false;
            applyToggleState(exeOnlyInput.closest('.psls-toggle'), false);
          }
        });
      }
      if (exeOnlyInput) {
        exeOnlyInput.addEventListener('change', function() {
          if (exeOnlyInput.checked && scanAllInput && scanAllInput.checked) {
            scanAllInput.checked = false;
            applyToggleState(scanAllInput.closest('.psls-toggle'), false);
          }
        });
      }

      // 扫描压缩文件内容 <-> 压缩包扫描深度 联动
      var scanArchivesInput = document.getElementById('opt-scan-archives');
      var archiveDepthSlider = document.getElementById('opt-archive-depth');
      var archiveDepthValue = document.getElementById('opt-archive-depth-value');
      function syncArchiveDepthEnabled() {
        if (archiveDepthSlider) {
          var enabled = scanArchivesInput ? scanArchivesInput.checked : true;
          archiveDepthSlider.disabled = !enabled;
          archiveDepthSlider.style.opacity = enabled ? '1' : '0.4';
          archiveDepthSlider.style.cursor = enabled ? 'pointer' : 'not-allowed';
        }
      }
      if (scanArchivesInput) {
        scanArchivesInput.addEventListener('change', syncArchiveDepthEnabled);
      }
      if (archiveDepthSlider) {
        archiveDepthSlider.addEventListener('input', function() {
          var val = parseInt(archiveDepthSlider.value, 10);
          if (archiveDepthValue) archiveDepthValue.textContent = val + ' 层';
        });
      }
      syncArchiveDepthEnabled();

      // 最大文件大小两处同步绑定（扫描页滑块、设置页输入框）
      // 签名库导入配置的"最大文件大小"独立，不参与同步
      var slider = document.getElementById('opt-max-size');
      var unlimitedCb = document.getElementById('opt-max-size-unlimited');
      var setInput = document.getElementById('set-max-size');
      var setUnlimitedCb = document.getElementById('set-max-size-unlimited');

      // 记录上一次有效的非无限制值（用于取消无限制时恢复）
      var lastMaxSizeValue = 50;

      if (slider) {
        slider.addEventListener('input', function() {
          var rawVal = parseInt(slider.value, 10) || 50;
          if (rawVal < MAX_SIZE_SLIDER_MAX) {
            lastMaxSizeValue = rawVal;
          }
          updateMaxSizeFromSlider(slider);
        });
      }
      if (unlimitedCb) {
        unlimitedCb.addEventListener('change', function() {
          if (unlimitedCb.checked) {
            // 勾选无限制：记录当前值用于恢复
            var curVal = parseInt(slider ? slider.value : '50', 10) || 50;
            if (curVal < MAX_SIZE_SLIDER_MAX) lastMaxSizeValue = curVal;
            updateMaxSizeUI(lastMaxSizeValue, true);
          } else {
            // 取消无限制：使用上一次有效值恢复
            updateMaxSizeUI(lastMaxSizeValue, false);
          }
        });
      }
      if (setInput) {
        setInput.addEventListener('input', function() {
          var size = parseInt(this.value, 10) || 1;
          if (size > 0 && size < MAX_SIZE_SLIDER_MAX) {
            lastMaxSizeValue = size;
            updateMaxSizeUI(size, false);
          } else if (size >= MAX_SIZE_SLIDER_MAX) {
            updateMaxSizeUI(MAX_SIZE_SLIDER_MAX, true);
          }
        });
      }
      if (setUnlimitedCb) {
        setUnlimitedCb.addEventListener('change', function() {
          if (setUnlimitedCb.checked) {
            var curVal = parseInt(setInput ? setInput.value : '50', 10) || 50;
            if (curVal < MAX_SIZE_SLIDER_MAX) lastMaxSizeValue = curVal;
            updateMaxSizeUI(lastMaxSizeValue, true);
          } else {
            updateMaxSizeUI(lastMaxSizeValue, false);
          }
        });
      }
      // 初始同步
      updateMaxSizeUI(50, false);

      // ===== 签名库导入配置的"最大文件大小"独立逻辑 =====
      var cfgInput = document.getElementById('cfg-size');
      var cfgUnlimitedCb = document.getElementById('cfg-size-unlimited');
      var lastCfgSizeValue = 50;
      if (cfgInput) {
        cfgInput.addEventListener('input', function() {
          var size = parseInt(this.value, 10) || 1;
          if (size > 0 && size < MAX_SIZE_SLIDER_MAX) {
            lastCfgSizeValue = size;
            if (cfgUnlimitedCb) cfgUnlimitedCb.checked = false;
          } else if (size >= MAX_SIZE_SLIDER_MAX) {
            if (cfgUnlimitedCb) cfgUnlimitedCb.checked = true;
            cfgInput.value = MAX_SIZE_SLIDER_MAX;
          }
        });
      }
      if (cfgUnlimitedCb) {
        cfgUnlimitedCb.addEventListener('change', function() {
          if (cfgUnlimitedCb.checked) {
            var curVal = parseInt(cfgInput ? cfgInput.value : '50', 10) || 50;
            if (curVal < MAX_SIZE_SLIDER_MAX) lastCfgSizeValue = curVal;
            if (cfgInput) { cfgInput.disabled = true; cfgInput.value = MAX_SIZE_SLIDER_MAX; }
          } else {
            if (cfgInput) { cfgInput.disabled = false; cfgInput.value = lastCfgSizeValue; }
          }
        });
      }
    }

    // ===== Dashboard buttons =====
    function initDashboardButtons() {
      // 「紧急终止」：**零确认，直接执行**（与回滚清场同一规则）
      // 现象 1 修复：反馈一律走应用内 toast（**不依赖 window.alert** —— WebView2 可能
      // 禁用脚本对话框，导致"点了没反应"），并且是否成功/排队都给出可见提示。
      var ctaEmergency = document.getElementById('cta-emergency');
      if (ctaEmergency) ctaEmergency.addEventListener('click', function() {
        try {
          if (!pyBridge) {
            if (typeof showInfoToast === 'function') {
              showInfoToast('紧急终止', '桥接尚未就绪，请稍后重试', 'warning', 2500);
            }
            return;
          }
          var res = pyBridge.emergencyTerminateAll(JSON.stringify({}));
          var obj = {};
          try { obj = JSON.parse(res || '{}'); } catch (e) { obj = {}; }
          if (obj && obj.error) {
            if (typeof showInfoToast === 'function') {
              showInfoToast('紧急终止', '执行失败：' + obj.error, 'warning', 3000);
            }
          } else if (obj && obj.pending) {
            if (typeof showInfoToast === 'function') {
              showInfoToast('紧急终止', '引擎初始化中，就绪后将自动执行', 'warning', 3000);
            }
          } else {
            if (typeof showInfoToast === 'function') {
              showInfoToast('紧急终止', '已开始终止非系统进程（详见活动日志）',
                            'success', 2500);
            }
          }
        } catch (e) {
          if (window.console) console.warn('[emergency] 调用失败', e);
          if (typeof showInfoToast === 'function') {
            showInfoToast('紧急终止', '调用异常：' + e, 'warning', 3000);
          }
        }
      });
      // 保留「智能扫描」原有能力入口（入口已从主界面移到扫描页可达）
      var ctaScan = document.getElementById('cta-scan');
      if (ctaScan) ctaScan.addEventListener('click', function() {
        navigateTo('scan');
      });
      var exportBtn = document.getElementById('btn-export-logs');
      if (exportBtn) exportBtn.addEventListener('click', function() {
        if (pyBridge) pyBridge.exportLogsDialog();
      });
    }

    // ===== 勒索回滚：快照范围与文件类型 =====
    var _rbSnapCfg = { dirs: [], exts: [], maxFileMb: 64 };
    var RB_COMMON_EXTS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
                          '.txt', '.jpg', '.png', '.zip', '.rar', '.7z', '.psd', '.mp4'];
    // 单文件快照上限滑动条：范围 1–256 MB，**最顶端(257) = 无限制(0)**。
    var RB_MAX_SIZE_TOP = 257;

    function rbMaxRawToMb(v) {
      v = parseInt(v, 10);
      if (isNaN(v) || v >= RB_MAX_SIZE_TOP) return 0;   // 顶端 → 无限制
      if (v <= 0) return 1;
      return v;
    }
    function rbMaxMbToRaw(mb) {
      mb = parseInt(mb, 10);
      if (isNaN(mb) || mb <= 0) return RB_MAX_SIZE_TOP;  // 无限制 → 顶端
      if (mb > 256) return RB_MAX_SIZE_TOP;
      return mb;
    }
    function rbMaxText(mb) { return (mb > 0) ? (mb + ' MB') : '无限制'; }

    function renderRbMaxSize() {
      var s = document.getElementById('rb-max-size');
      if (!s) return;
      var lbl = document.getElementById('rb-max-size-val');
      if (lbl) lbl.textContent = rbMaxText(rbMaxRawToMb(s.value));
    }

    function renderRollbackSnapshotConfig() {
      // 保护目录列表：**复用与"扫描排除项"完全相同的渲染**（调整 3）
      renderPathList('rb-dir-list', _rbSnapCfg.dirs, function(i) {
        if (i >= 0 && i < _rbSnapCfg.dirs.length) {
          _rbSnapCfg.dirs.splice(i, 1);
          renderRollbackSnapshotConfig();
        }
      }, '（未指定，使用默认：桌面/文档/下载/图片/视频/音乐）');
      var chips = document.getElementById('rb-ext-chips');
      if (chips) {
        chips.innerHTML = '';
        var all = !_rbSnapCfg.exts.length;
        var list = RB_COMMON_EXTS.slice();
        _rbSnapCfg.exts.forEach(function(e) { if (list.indexOf(e) < 0) list.push(e); });
        list.forEach(function(e) {
          var on = (!all && _rbSnapCfg.exts.indexOf(e) >= 0);
          var chip = document.createElement('button');
          chip.setAttribute('data-action', 'rb-toggle-ext');
          chip.setAttribute('data-ext', e);
          chip.style.cssText = 'font-size:12px; padding:3px 10px; border-radius:9999px; cursor:pointer; border:1px solid ' +
            (on ? 'var(--psls-primary)' : 'var(--psls-border)') + '; background-color:' +
            (on ? 'var(--psls-primary)' : 'var(--psls-secondary)') + '; color:' +
            (on ? 'var(--psls-primary-foreground)' : 'var(--psls-secondary-foreground)') + ';';
          chip.textContent = e;
          chips.appendChild(chip);
        });
      }
      var allBox = document.getElementById('rb-ext-all');
      if (allBox) allBox.checked = !_rbSnapCfg.exts.length;
      renderRbMaxSize();
    }

    function loadRollbackSnapshotConfig() {
      try {
        if (pyBridge && typeof pyBridge.getRollbackSnapshotConfig === 'function') {
          var raw = pyBridge.getRollbackSnapshotConfig();
          var obj = (typeof raw === 'string') ? JSON.parse(raw) : raw;
          if (obj && typeof obj === 'object') {
            _rbSnapCfg.dirs = Array.isArray(obj.dirs) ? obj.dirs.slice() : [];
            _rbSnapCfg.exts = Array.isArray(obj.exts) ? obj.exts.slice() : [];
            _rbSnapCfg.maxFileMb = (obj.max_file_mb === 0) ? 0
              : (parseInt(obj.max_file_mb, 10) > 0 ? parseInt(obj.max_file_mb, 10) : 64);
          }
        }
        // 回填单文件上限滑动条（0=无限制 → 顶端）
        var sizeEl = document.getElementById('rb-max-size');
        if (sizeEl) sizeEl.value = rbMaxMbToRaw(_rbSnapCfg.maxFileMb);
        // 调整 3：未配置时**默认展示**引擎的系统常用目录（桌面/文档/下载/图片/视频/音乐，
      // 来源以引擎 get_protected_dirs() 为准，避免前端硬编码与引擎不一致）。
        if (!_rbSnapCfg.dirs.length && pyBridge
            && typeof pyBridge.getRollbackDefaultDirs === 'function') {
          var dRaw = pyBridge.getRollbackDefaultDirs();
          var dobj = (typeof dRaw === 'string') ? JSON.parse(dRaw) : (dRaw || {});
          var defs = (dobj && dobj.dirs) ? dobj.dirs : [];
          if (defs.length) _rbSnapCfg.dirs = defs.slice();
        }
      } catch(e) {}
      renderRollbackSnapshotConfig();
    }

    function initRollbackSnapshotConfig() {
      var dirList = document.getElementById('rb-dir-list');
      if (!dirList) return;
      // 保护目录：复用统一编辑器（输入 + 浏览 + 添加；与"扫描排除项"同一套）
      initPathListEditor({
        inputId: 'rb-dir-input',
        addBtnId: 'rb-dir-add',
        browseBtnId: 'rb-dir-browse',
        onAdd: function(v) {
          if (_rbSnapCfg.dirs.indexOf(v) < 0) _rbSnapCfg.dirs.push(v);
          renderRollbackSnapshotConfig();
        }
      });
      var chips = document.getElementById('rb-ext-chips');
      if (chips) chips.addEventListener('click', function(e) {
        var btn = e.target.closest ? e.target.closest('[data-action="rb-toggle-ext"]') : null;
        if (!btn) return;
        var ext = btn.getAttribute('data-ext');
        var i = _rbSnapCfg.exts.indexOf(ext);
        if (i >= 0) _rbSnapCfg.exts.splice(i, 1); else _rbSnapCfg.exts.push(ext);
        renderRollbackSnapshotConfig();
      });
      var addExtBtn = document.querySelector('[data-action="rb-add-ext"]');
      if (addExtBtn) addExtBtn.addEventListener('click', function() {
        var inp = document.getElementById('rb-ext-input');
        if (!inp) return;
        (inp.value || '').split(',').forEach(function(p) {
          var s = p.trim().toLowerCase();
          if (!s) return;
          if (s.charAt(0) !== '.') s = '.' + s;
          if (_rbSnapCfg.exts.indexOf(s) < 0) _rbSnapCfg.exts.push(s);
        });
        inp.value = '';
        renderRollbackSnapshotConfig();
      });
      var allBox = document.getElementById('rb-ext-all');
      if (allBox) allBox.addEventListener('change', function() {
        if (this.checked) _rbSnapCfg.exts = [];
        renderRollbackSnapshotConfig();
      });
      // 单文件快照上限滑动条：拖动即时刷新文案（最顶端 = 无限制）
      var sizeEl = document.getElementById('rb-max-size');
      if (sizeEl) {
        sizeEl.addEventListener('input', renderRbMaxSize);
        sizeEl.addEventListener('change', renderRbMaxSize);
      }
      var saveBtn = document.querySelector('[data-action="rb-save-config"]');
      if (saveBtn) saveBtn.addEventListener('click', function() {
        var ok = true;
        var maxMb = rbMaxRawToMb((document.getElementById('rb-max-size') || {}).value);
        try {
          if (pyBridge && typeof pyBridge.setRollbackSnapshotConfig === 'function') {
            ok = pyBridge.setRollbackSnapshotConfig(
              JSON.stringify({ dirs: _rbSnapCfg.dirs, exts: _rbSnapCfg.exts,
                               max_file_mb: maxMb }));
          }
        } catch(e) { ok = false; }
        var st = document.getElementById('rb-snap-state');
        if (st) st.textContent = (ok === false) ? '保存失败' : '已保存';
        showInfoToast('勒索文件回滚', (ok === false) ? '快照范围保存失败' : '快照范围已保存',
                      (ok === false) ? 'warning' : 'success', 2500);
        if (ok !== false) loadRollbackSnapshotConfig();
      });
      if (window.lucide) lucide.createIcons();
      loadRollbackSnapshotConfig();
    }

    // ===== Settings browse button =====
    var _settingsButtonsInitialized = false;
    function initSettingsButtons() {
      if (_settingsButtonsInitialized) return;
      _settingsButtonsInitialized = true;
      initRollbackSnapshotConfig();
      var browseBtn = document.getElementById('set-browse');
      if (browseBtn) browseBtn.addEventListener('click', function() {
        if (pyBridge) {
          pyBridge.setBrowseTarget('set-scan-path');
          pyBridge.browseFolder();
        }
      });
      // 通知开关联动：设置页"桌面通知" 和 "发现威胁时弹窗" 与扫描页"检测到威胁时通知"同步
      var setNotify = document.getElementById('set-notify');
      var setThreatPopup = document.getElementById('set-threat-popup');
      var optNotifyThreat = document.getElementById('opt-notify-threat');
      // 设置页 -> 扫描页
      function syncToScanPage() {
        if (!optNotifyThreat) return;
        var enabled = (setNotify && setNotify.checked) || (setThreatPopup && setThreatPopup.checked);
        optNotifyThreat.checked = enabled;
        applyToggleState(optNotifyThreat.closest('.psls-toggle'), enabled);
      }
      if (setNotify) setNotify.addEventListener('change', syncToScanPage);
      if (setThreatPopup) setThreatPopup.addEventListener('change', syncToScanPage);
      // 扫描页 -> 设置页
      if (optNotifyThreat) {
        optNotifyThreat.addEventListener('change', function() {
          if (setThreatPopup) {
            setThreatPopup.checked = optNotifyThreat.checked;
            applyToggleState(setThreatPopup.closest('.psls-toggle'), optNotifyThreat.checked);
          }
          if (setNotify && optNotifyThreat.checked && !setNotify.checked) {
            setNotify.checked = true;
            applyToggleState(setNotify.closest('.psls-toggle'), true);
          }
        });
      }
      // 初始同步
      syncToScanPage();
      // 声音提醒开关：独立控制提示音
      var setSound = document.getElementById('set-sound');
      if (setSound) {
        setSound.addEventListener('change', function() {
          if (pyBridge) pyBridge.setSoundEnabled(this.checked);
          applyToggleState(this.closest('.psls-toggle'), this.checked);
        });
        // 初始同步到后端
        if (pyBridge) pyBridge.setSoundEnabled(setSound.checked);
      }
      // 新文件扫描结果弹窗开关：独立控制
      var setNewFilePopup = document.getElementById('set-new-file-result-popup');
      if (setNewFilePopup) {
        setNewFilePopup.addEventListener('change', function() {
          if (pyBridge && typeof pyBridge.setNewFileResultPopupEnabled === 'function') {
            pyBridge.setNewFileResultPopupEnabled(this.checked);
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
        });
        // 初始同步到后端（若 updateDashboardData 还没同步到状态，就先按 UI 状态发一次）
        if (pyBridge && typeof pyBridge.setNewFileResultPopupEnabled === 'function') {
          pyBridge.setNewFileResultPopupEnabled(setNewFilePopup.checked);
        }
      }
      // 更激进的特效检测开关：默认关闭，独立控制（截图监控，需谨慎开启）
      var setAggPrank = document.getElementById('set-aggressive-prank');
      if (setAggPrank) {
        setAggPrank.addEventListener('change', function() {
          if (pyBridge && typeof pyBridge.setAggressivePrankEnabled === 'function') {
            pyBridge.setAggressivePrankEnabled(this.checked);
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
        });
        // 初始同步：以后端状态为准（默认关闭，避免页面刷新导致开关状态串改）
        try {
          if (pyBridge && typeof pyBridge.getAggressivePrankStatus === 'function') {
            var applyAggPrankState = function(v) {
              var checked = (v === true || v === 'true');
              setAggPrank.checked = checked;
              applyToggleState(setAggPrank.closest('.psls-toggle'), checked);
            };
            var aggrStatus = pyBridge.getAggressivePrankStatus();
            if (aggrStatus && typeof aggrStatus.then === 'function') {
              aggrStatus.then(applyAggPrankState).catch(function() {});
            } else {
              applyAggPrankState(!!aggrStatus);
            }
          }
        } catch(e) {}
      }
      // 勒索文件回滚开关：默认开启，独立控制（挂后台快照线程）
      var setRansomwareRollback = document.getElementById('set-ransomware-rollback');
      if (setRansomwareRollback) {
        setRansomwareRollback.addEventListener('change', function() {
          if (pyBridge && typeof pyBridge.setRansomwareRollbackEnabled === 'function') {
            pyBridge.setRansomwareRollbackEnabled(this.checked);
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
        });
        // 初始同步：以后端状态为准
        try {
          if (pyBridge && typeof pyBridge.getRansomwareRollbackStatus === 'function') {
            var rbStatus = pyBridge.getRansomwareRollbackStatus();
            var applyRbState = function(v) {
              var obj = null;
              try { obj = (typeof v === 'string') ? JSON.parse(v) : v; } catch(e) { obj = null; }
              if (!obj || typeof obj !== 'object') return;
              var checked = (obj.enabled !== false);
              setRansomwareRollback.checked = checked;
              applyToggleState(setRansomwareRollback.closest('.psls-toggle'), checked);
            };
            if (rbStatus && typeof rbStatus.then === 'function') {
              rbStatus.then(applyRbState).catch(function() {});
            } else {
              applyRbState(rbStatus);
            }
          }
        } catch(e) {}
      }
      // 威胁处理方式：设置页与扫描页两组下拉统一到同一份设置（含 localStorage 兜底 + 写后端）
      bindThreatActionSelects();
      // 开机自启开关：通过注册表设置/取消开机自启
      var setAutorun = document.getElementById('set-autorun');
      if (setAutorun) {
        setAutorun.addEventListener('change', function() {
          if (pyBridge) {
            var ok = pyBridge.setAutoStart(this.checked);
            // 如果操作失败，回滚开关状态
            if (ok === false) {
              this.checked = !this.checked;
            }
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
        });
      }
      // YARA 引擎开关：启用/禁用 YARA 规则引擎
      var setYara = document.getElementById('set-yara');
      if (setYara) {
        setYara.addEventListener('change', function() {
          if (pyBridge) {
            var ok = pyBridge.setYaraEnabled(this.checked);
            if (ok === false) {
              this.checked = !this.checked;
            }
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
          // 状态刷新依赖 Python 信号推送（ruleEngineStatusChanged），不再主动轮询
        });
      }
      // ML 引擎开关：启用/禁用 ML 检测引擎
      var setMl = document.getElementById('set-ml');
      if (setMl) {
        setMl.addEventListener('change', function() {
          if (pyBridge && pyBridge.setMlEnabled) {
            pyBridge.setMlEnabled(this.checked);
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
          // 状态刷新依赖 Python 信号推送（mlEngineStatusChanged）
        });
      }
      // LightGBM 补充引擎开关
      var setLightGBM = document.getElementById('set-lightgbm');
      if (setLightGBM) {
        setLightGBM.addEventListener('change', function() {
          if (pyBridge && pyBridge.setLightGBMEnabled) {
            pyBridge.setLightGBMEnabled(this.checked);
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
        });
      }
      // 自我保护为强制开启，设置中已移除开关与相关信息（V26.1.4+）

      // 严格模式开关：启用更激进的检测策略
      var setStrictMode = document.getElementById('set-strict-mode');
      var setStrictModeLabel = document.getElementById('set-strict-mode-label');
      if (setStrictMode) {
        setStrictMode.addEventListener('change', function() {
          console.log('[DEBUG setStrictMode] change fired, checked=', this.checked, 'pyBridge=', !!pyBridge);
          if (_strictModeSyncing) return;
          // 立即更新本地 UI（不依赖后端返回值）
          if (setStrictModeLabel) {
            setStrictModeLabel.textContent = this.checked ? '已启用' : '已关闭';
            setStrictModeLabel.style.color = this.checked ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
          }
          try { localStorage.setItem('psls:strict-mode', this.checked ? '1' : '0'); } catch (e) {}
          if (pyBridge && pyBridge.setStrictMode) {
            try {
              pyBridge.setStrictMode(this.checked);
            } catch(e) {
              console.warn('setStrictMode 调用异常:', e);
            }
          }
          return; // 已立即更新，不再走 result.success 分支
        });
      }
      // 兼容旧代码：保留 result.success 分支（已禁用）
      if (false) {
        setStrictMode.addEventListener('change', function() {
          if (pyBridge && pyBridge.setStrictMode) {
            var raw = pyBridge.setStrictMode(this.checked);
            var result = (typeof raw === 'string') ? JSON.parse(raw) : (raw || {});
            if (result && result.success) {
              if (setStrictModeLabel) {
                setStrictModeLabel.textContent = this.checked ? '已启用' : '已关闭';
                setStrictModeLabel.style.color = this.checked ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
              }
              try { localStorage.setItem('psls:strict-mode', this.checked ? '1' : '0'); } catch (e) {}
              if (typeof showInfoToast === 'function') {
                var modeName = this.checked ? '严格模式' : '宽松模式';
                showInfoToast('严格模式', '已切换到' + modeName, 'success', 2000);
              }
            } else {
              _strictModeSyncing = true;
              this.checked = !this.checked;
              applyToggleState(this.closest('.psls-toggle'), this.checked);
              _strictModeSyncing = false;
              if (typeof showInfoToast === 'function') {
                showInfoToast('严格模式', result && result.message ? result.message : '操作失败', 'error', 3000);
              }
            }
          } else {
            _strictModeSyncing = true;
            this.checked = !this.checked;
            applyToggleState(this.closest('.psls-toggle'), this.checked);
            _strictModeSyncing = false;
          }
        });
      }
      // 严格模式状态完全依赖 Python 信号推送（strictModeStatusChanged）

      // VirusIdentifier 检测开关（纯启发式引擎，误报偏高，默认关闭）
      var setVirusIdentifier = document.getElementById('set-virus-identifier');
      var setVirusIdentifierLabel = document.getElementById('set-virus-identifier-label');
      var _virusIdentifierSyncing = false;
      if (setVirusIdentifier) {
        setVirusIdentifier.addEventListener('change', function() {
          if (_virusIdentifierSyncing) return;
          if (setVirusIdentifierLabel) {
            setVirusIdentifierLabel.textContent = this.checked ? '已启用' : '已关闭';
            setVirusIdentifierLabel.style.color = this.checked ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
          try { localStorage.setItem('psls:virus-identifier', this.checked ? '1' : '0'); } catch (e) {}
          if (pyBridge && pyBridge.setVirusIdentifier) {
            try {
              pyBridge.setVirusIdentifier(this.checked);
            } catch(e) {
              console.warn('setVirusIdentifier 调用异常:', e);
              this.checked = !this.checked;
              applyToggleState(this.closest('.psls-toggle'), this.checked);
              if (setVirusIdentifierLabel) {
                setVirusIdentifierLabel.textContent = this.checked ? '已启用' : '已关闭';
                setVirusIdentifierLabel.style.color = this.checked ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
              }
            }
          } else {
            this.checked = !this.checked;
            applyToggleState(this.closest('.psls-toggle'), this.checked);
          }
        });
      }

      // 监测全部类型的文件开关
      var setMonitorAllTypes = document.getElementById('set-monitor-all-types');
      var setMonitorAllTypesLabel = document.getElementById('set-monitor-all-types-label');
      var _monitorAllTypesSyncing = false;
      if (setMonitorAllTypes) {
        setMonitorAllTypes.addEventListener('change', function() {
          if (_monitorAllTypesSyncing) return;
          // 立即更新本地 UI（与严格模式/自我保护相同的Fire-and-Forget模式）
          if (setMonitorAllTypesLabel) {
            setMonitorAllTypesLabel.textContent = this.checked ? '已启用' : '已关闭';
            setMonitorAllTypesLabel.style.color = this.checked ? 'var(--psls-c-accent)' : 'var(--psls-c-gray-text)';
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
          try { localStorage.setItem('psls:monitor-all-types', this.checked ? '1' : '0'); } catch (e) {}
          if (pyBridge && pyBridge.setMonitorAllFileTypes) {
            try {
              // 调用后端，不检查返回值；状态同步完全依赖 Python 信号（monitorAllFileTypesStatusChanged）
              // 如果严格模式不允许关闭，后端会通过信号推送 enabled=true，前端会收到后自动回滚
              pyBridge.setMonitorAllFileTypes(this.checked);
            } catch(e) {
              console.warn('setMonitorAllFileTypes 调用异常:', e);
              // 回滚（仅当JS层调用异常时触发，否则通过信号同步处理）
              this.checked = !this.checked;
              applyToggleState(this.closest('.psls-toggle'), this.checked);
              if (setMonitorAllTypesLabel) {
                setMonitorAllTypesLabel.textContent = this.checked ? '已启用' : '已关闭';
                setMonitorAllTypesLabel.style.color = this.checked ? 'var(--psls-c-accent)' : 'var(--psls-c-gray-text)';
              }
            }
          } else {
            this.checked = !this.checked;
            applyToggleState(this.closest('.psls-toggle'), this.checked);
          }
        });
      }
      // 监测全部文件类型状态完全依赖 Python 信号推送（monitorAllFileTypesStatusChanged）

      // 大文件沙箱分析开关
      var setSandboxLargeFiles = document.getElementById('set-sandbox-large-files');
      var setSandboxLargeFilesLabel = document.getElementById('set-sandbox-large-files-label');
      if (setSandboxLargeFiles) {
        setSandboxLargeFiles.addEventListener('change', function() {
          if (_sandboxLargeFilesSyncing) return;
          if (setSandboxLargeFilesLabel) {
            setSandboxLargeFilesLabel.textContent = this.checked ? '已启用' : '已关闭';
            setSandboxLargeFilesLabel.style.color = this.checked ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
          }
          applyToggleState(this.closest('.psls-toggle'), this.checked);
          try { localStorage.setItem('psls:sandbox-large-files', this.checked ? '1' : '0'); } catch (e) {}
          if (pyBridge && pyBridge.setSandboxRunLargeFiles) {
            try {
              pyBridge.setSandboxRunLargeFiles(this.checked);
            } catch(e) {
              console.warn('setSandboxRunLargeFiles 调用异常:', e);
              this.checked = !this.checked;
              applyToggleState(this.closest('.psls-toggle'), this.checked);
              if (setSandboxLargeFilesLabel) {
                setSandboxLargeFilesLabel.textContent = this.checked ? '已启用' : '已关闭';
                setSandboxLargeFilesLabel.style.color = this.checked ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
              }
            }
          } else {
            this.checked = !this.checked;
            applyToggleState(this.closest('.psls-toggle'), this.checked);
          }
        });
      }
      // 大文件沙箱分析状态完全依赖 Python 信号推送（sandboxRunLargeFilesStatusChanged）

      // ===== 隔离区路径设置 =====
      var browseQuarantineBtn = document.getElementById('btn-browse-quarantine');

      // 选择隔离区路径
      if (browseQuarantineBtn) {
        browseQuarantineBtn.addEventListener('click', function() {
          if (pyBridge) {
            pyBridge.setBrowseTarget('quarantine-path-select');
            pyBridge.browseFolder();
          }
        });
      }

      // ===== 实时监控范围设置 =====
      function initRtScopeRadios() {
        var radios = document.querySelectorAll('.rt-scope-radio');
        var customBox = document.getElementById('rt-custom-paths');
        for (var i = 0; i < radios.length; i++) {
          radios[i].addEventListener('change', function() {
            if (customBox) {
              customBox.style.display = this.value === 'custom' ? 'block' : 'none';
            }
            saveRtScope();
          });
        }

        var addBtn = document.getElementById('rt-path-add');
        var pathInput = document.getElementById('rt-path-input');
        if (addBtn && pathInput) {
          addBtn.addEventListener('click', function() {
            var val = pathInput.value.trim();
            if (val && _rtCustomPaths.indexOf(val) === -1) {
              _rtCustomPaths.push(val);
              pathInput.value = '';
              renderRtPathList();
              saveRtScope();
            }
          });
          pathInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
              addBtn.click();
            }
          });
        }

        var browseBtn = document.getElementById('rt-path-browse');
        if (browseBtn) {
          browseBtn.addEventListener('click', function() {
            if (pyBridge) {
              pyBridge.setBrowseTarget('rt-path-input');
              pyBridge.browseFolder();
              // 目录选择后，在输入框值变化时自动添加
              setTimeout(function() {
                if (pathInput && pathInput.value.trim()) {
                  addBtn.click();
                }
              }, 200);
            }
          });
        }
      }
      initRtScopeRadios();
      initScanExcludePaths();

      // ===== 更新日志按钮 =====
      var changelogBtn = document.getElementById('btn-view-changelog');
      if (changelogBtn) {
        changelogBtn.addEventListener('click', function() {
          navigateTo('changelog');
          if (window.lucide) lucide.createIcons();
        });
      }
      // 更新日志页返回按钮
      var changelogBackBtn = document.querySelector('[data-action="back-to-settings"]');
      if (changelogBackBtn) {
        changelogBackBtn.addEventListener('click', function() {
          navigateTo('settings');
        });
      }
    }

    // ===== 实时监控范围设置（全局） =====
    var _rtCustomPaths = [];

    function renderRtPathList() {
      var listEl = document.getElementById('rt-path-list');
      if (!listEl) return;
      listEl.innerHTML = '';
      _rtCustomPaths.forEach(function(path, idx) {
        var row = document.createElement('div');
        row.className = 'flex items-center gap-2';
        row.style.cssText = 'padding:4px 8px; border-radius:4px; background-color:var(--psls-muted);';
        var span = document.createElement('span');
        span.className = 'flex-1 text-xs';
        span.style.cssText = 'color:var(--psls-card-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
        span.title = path;
        span.textContent = path;
        var delBtn = document.createElement('button');
        delBtn.className = 'text-xs';
        delBtn.style.cssText = 'color:var(--psls-c-danger-text); background:transparent; border:none; cursor:pointer; padding:2px 6px;';
        delBtn.textContent = '删除';
        delBtn.addEventListener('click', function() {
          _rtCustomPaths.splice(idx, 1);
          renderRtPathList();
          saveRtScope();
        });
        row.appendChild(span);
        row.appendChild(delBtn);
        listEl.appendChild(row);
      });
    }

    function saveRtScope() {
      if (!pyBridge) return;
      var scope = 'critical';
      var radios = document.querySelectorAll('.rt-scope-radio');
      for (var i = 0; i < radios.length; i++) {
        if (radios[i].checked) {
          scope = radios[i].value;
          break;
        }
      }
      var paths = scope === 'custom' ? _rtCustomPaths.slice() : [];
      try {
        pyBridge.setRealtimeScope(scope, JSON.stringify(paths));
      } catch(e) {
        console.warn('setRealtimeScope 调用异常:', e);
      }
    }

    // ===== 通用"路径列表"编辑器（**扫描排除项 与 回滚保护目录 共用同一实现**）=====
    // 需求（调整 3）：两处 UI 必须完全一致（列表 + 输入 + 浏览 + 添加 + 删除 + 保存），
    // 因此抽出这一套渲染/交互，避免各写一份导致风格与行为漂移。
    function renderPathList(listElId, paths, onDelete, emptyText) {
      var listEl = document.getElementById(listElId);
      if (!listEl) return;
      listEl.innerHTML = '';
      if (!paths || paths.length === 0) {
        var empty = document.createElement('div');
        empty.style.cssText = 'font-size:12px; color:var(--psls-muted-foreground); padding:4px 0;';
        empty.textContent = emptyText || '暂无排除路径';
        listEl.appendChild(empty);
        return;
      }
      paths.forEach(function(path, idx) {
        var row = document.createElement('div');
        row.className = 'flex items-center gap-2';
        row.style.cssText = 'padding:4px 8px; border-radius:4px; background-color:var(--psls-muted);';
        var span = document.createElement('span');
        span.className = 'flex-1 text-xs';
        span.style.cssText = 'color:var(--psls-card-foreground); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
        span.title = path;
        span.textContent = path;
        var delBtn = document.createElement('button');
        delBtn.className = 'text-xs';
        delBtn.style.cssText = 'color:var(--psls-c-danger-text); background:transparent; border:none; cursor:pointer; padding:2px 6px;';
        delBtn.textContent = '删除';
        delBtn.addEventListener('click', function() { onDelete(idx); });
        row.appendChild(span);
        row.appendChild(delBtn);
        listEl.appendChild(row);
      });
    }

    // 统一的"输入 + 浏览 + 添加"交互绑定（扫描排除项 / 回滚保护目录 共用）
    function initPathListEditor(opts) {
      var input = document.getElementById(opts.inputId);
      var addBtn = document.getElementById(opts.addBtnId);
      var browseBtn = document.getElementById(opts.browseBtnId);
      if (!input || !addBtn) return;
      addBtn.addEventListener('click', function() {
        var v = (input.value || '').trim();
        if (!v) return;
        opts.onAdd(v);
        input.value = '';
      });
      input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') addBtn.click();
      });
      if (browseBtn) {
        browseBtn.addEventListener('click', function() {
          if (!pyBridge) return;
          try {
            pyBridge.setBrowseTarget(opts.inputId);
            pyBridge.browseFolder();
          } catch (e) { console.warn('browseFolder 调用异常:', e); }
          setTimeout(function() {
            if (input && input.value.trim()) addBtn.click();
          }, 200);
        });
      }
    }

    // ===== 扫描排除路径设置（全局） =====
    var _scanExcludedPaths = [];

    function renderScanExcludeList() {
      renderPathList('scan-exclude-list', _scanExcludedPaths, function(idx) {
        _scanExcludedPaths.splice(idx, 1);
        renderScanExcludeList();
        saveScanExcludedPaths();
      }, '暂无排除路径');
    }

    function saveScanExcludedPaths() {
      if (!pyBridge) return;
      try {
        pyBridge.setScanExcludedPaths(JSON.stringify(_scanExcludedPaths));
      } catch(e) {
        console.warn('setScanExcludedPaths 调用异常:', e);
      }
    }

    function initScanExcludePaths() {
      // 加载已有排除路径（QWebChannel 可能返回 Promise 或直接返回字符串）
      try {
        if (pyBridge && pyBridge.getScanExcludedPaths) {
          var raw = pyBridge.getScanExcludedPaths();
          var applyData = function(d) {
            _scanExcludedPaths = (d.paths || []).slice();
            renderScanExcludeList();
          };
          if (raw && typeof raw.then === 'function') {
            raw.then(function(r) {
              var d = (typeof r === 'string') ? JSON.parse(r) : (r || {});
              applyData(d);
            }).catch(function(e) { console.warn('获取扫描排除路径失败:', e); });
          } else {
            var data = (typeof raw === 'string') ? JSON.parse(raw) : (raw || {});
            applyData(data);
          }
        }
      } catch(e) {
        console.warn('获取扫描排除路径失败:', e);
      }

      var addBtn = document.getElementById('scan-exclude-add');
      var pathInput = document.getElementById('scan-exclude-input');
      // 复用统一编辑器（与回滚保护目录同一套交互：输入 + 浏览 + 添加）
      initPathListEditor({
        inputId: 'scan-exclude-input',
        addBtnId: 'scan-exclude-add',
        browseBtnId: 'scan-exclude-browse',
        onAdd: function(v) {
          if (_scanExcludedPaths.indexOf(v) === -1) {
            _scanExcludedPaths.push(v);
            renderScanExcludeList();
            saveScanExcludedPaths();
          }
        }
      });
    }

    // 同步严格模式状态到 UI
    function syncStrictModeStatus() {
      try {
        if (!pyBridge || !pyBridge.getStrictMode) {
          console.log('[DEBUG syncStrictModeStatus] pyBridge not ready');
          return;
        }
        var raw = pyBridge.getStrictMode();
        console.log('[DEBUG syncStrictModeStatus] raw type=', typeof raw, 'value=', raw);
        var status = {};
        try { status = JSON.parse(raw) || {}; } catch (e) { status = {}; }
        var backendEnabled = !!status.enabled;
        var storedVal = null;
        try { storedVal = localStorage.getItem('psls:strict-mode'); } catch (e) {}
        var storedEnabled = storedVal === '1';
        var enabled = backendEnabled;
        console.log('[DEBUG syncStrictModeStatus] backendEnabled=', backendEnabled, 'storedEnabled=', storedEnabled);
        if (storedVal !== null && storedEnabled !== backendEnabled) {
          if (pyBridge.setStrictMode) {
            try {
              var syncRaw = pyBridge.setStrictMode(storedEnabled);
              console.log('[DEBUG syncStrictModeStatus] setStrictMode raw=', syncRaw);
              var syncResult = {};
              try { syncResult = JSON.parse(syncRaw) || {}; } catch(e) { syncResult = {}; }
              if (syncResult && syncResult.success) {
                enabled = storedEnabled;
              }
            } catch(e) {
              console.warn('同步严格模式到后端失败:', e);
            }
          }
        }
        var toggle = document.getElementById('set-strict-mode');
        var label = document.getElementById('set-strict-mode-label');
        if (toggle) {
          _strictModeSyncing = true;
          toggle.checked = enabled;
          applyToggleState(toggle.closest('.psls-toggle'), enabled);
          _strictModeSyncing = false;
        }
        if (label) {
          label.textContent = enabled ? '已启用' : '已关闭';
          label.style.color = enabled ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
        }
      } catch (e) {
        console.warn('同步严格模式状态失败:', e);
      }
    }

    // 同步监测全部文件类型状态到 UI
    function syncMonitorAllFileTypesStatus() {
      try {
        if (!pyBridge || !pyBridge.getMonitorAllFileTypes) return;
        var raw = pyBridge.getMonitorAllFileTypes();
        var status = {};
        if (typeof raw === 'string') {
          try { status = JSON.parse(raw) || {}; } catch (e) { status = {}; }
        } else if (raw && typeof raw === 'object') {
          status = raw;
        }
        var backendEnabled = !!status.enabled;
        var storedVal = null;
        try { storedVal = localStorage.getItem('psls:monitor-all-types'); } catch (e) {}
        var storedEnabled = storedVal === null ? true : (storedVal === '1');
        var enabled = backendEnabled;
        // localStorage 与后端不一致时，以后端为准并更新 localStorage
        if (storedVal !== null && storedEnabled !== backendEnabled) {
          try { localStorage.setItem('psls:monitor-all-types', backendEnabled ? '1' : '0'); } catch (e) {}
        }
        var toggle = document.getElementById('set-monitor-all-types');
        var label = document.getElementById('set-monitor-all-types-label');
        if (toggle) {
          _monitorAllTypesSyncing = true;
          toggle.checked = enabled;
          applyToggleState(toggle.closest('.psls-toggle'), enabled);
          _monitorAllTypesSyncing = false;
        }
        if (label) {
          label.textContent = enabled ? '已启用' : '已关闭';
          label.style.color = enabled ? 'var(--psls-c-accent)' : 'var(--psls-c-gray-text)';
        }
        // 同步扫描页默认选项
        syncScanPageOptions(enabled);
      } catch (e) {
        console.warn('同步监测全部文件类型状态失败:', e);
      }
    }

    // 同步大文件沙箱分析开关状态到 UI（后端默认 False，localStorage 有值时以它为准）
    function syncSandboxLargeFilesStatus() {
      try {
        if (!pyBridge) return;
        var storedVal = null;
        try { storedVal = localStorage.getItem('psls:sandbox-large-files'); } catch (e) {}
        if (storedVal === null) return; // 无存储记录则用后端默认
        var storedEnabled = storedVal === '1';
        // 同步到后端
        if (pyBridge.setSandboxRunLargeFiles) {
          try { pyBridge.setSandboxRunLargeFiles(storedEnabled); } catch (e) {}
        }
        // 同步 UI
        var toggle = document.getElementById('set-sandbox-large-files');
        var label = document.getElementById('set-sandbox-large-files-label');
        if (toggle) {
          _sandboxLargeFilesSyncing = true;
          toggle.checked = storedEnabled;
          applyToggleState(toggle.closest('.psls-toggle'), storedEnabled);
          _sandboxLargeFilesSyncing = false;
        }
        if (label) {
          label.textContent = storedEnabled ? '已启用' : '已关闭';
          label.style.color = storedEnabled ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
        }
      } catch (e) {
        console.warn('同步大文件沙箱开关状态失败:', e);
      }
    }

    // 同步扫描页选项默认值
    // 默认勾选"仅扫描可执行文件和压缩包"，不联动全局"监测全部类型"设置
    function syncScanPageOptions(monitorAllTypes) {
      var scanAllInput = document.getElementById('opt-scan-all');
      var exeOnlyInput = document.getElementById('opt-exe-only');
      if (!scanAllInput || !exeOnlyInput) return;
      // 始终默认勾选"仅扫描可执行文件和压缩包"
      scanAllInput.checked = false;
      applyToggleState(scanAllInput.closest('.psls-toggle'), false);
      exeOnlyInput.checked = true;
      applyToggleState(exeOnlyInput.closest('.psls-toggle'), true);
    }

    // 同步自我保护状态到 UI
    function syncSelfProtectionStatus() {
      try {
        if (!pyBridge || !pyBridge.getSelfProtectionStatus) {
          console.log('[DEBUG syncSelfProtectionStatus] pyBridge not ready');
          return;
        }
        var raw = pyBridge.getSelfProtectionStatus();
        console.log('[DEBUG syncSelfProtectionStatus] raw type=', typeof raw, 'value=', raw);
        var status = {};
        if (typeof raw === 'string') {
          try { status = JSON.parse(raw) || {}; } catch (e) { status = {}; }
        } else if (raw && typeof raw === 'object') {
          status = raw;
        }
        var enabled = status.enabled !== false;
        var running = !!status.running;
        var state = status.state || (running ? 'running' : (enabled ? 'starting' : 'stopped'));
        console.log('[DEBUG syncSelfProtectionStatus] enabled=', enabled, 'running=', running, 'state=', state);

        // 主页指示灯（统一缓存渲染）
        if (!enabled) {
          dashSetItem('self-protection', '自我保护', 'red', '已关闭');
        } else if (state === 'uninitialized' || state === 'starting') {
          dashSetItem('self-protection', '自我保护', 'yellow', '启动中...');
        } else if (running) {
          dashSetItem('self-protection', '自我保护', 'green', '已启用');
        } else {
          dashSetItem('self-protection', '自我保护', 'gray', '已停止');
        }
      } catch (e) {
        console.warn('同步自我保护状态失败:', e);
      }
    }

    // ===== 直接应用状态（由 Python 信号推送触发，不依赖轮询）=====
    function applySelfProtectionStatus(status) {
      try {
        var enabled = status.enabled !== false;
        var running = !!status.running;
        var state = status.state || (running ? 'running' : (enabled ? 'starting' : 'stopped'));
        console.log('[APPLY SP] enabled=', enabled, 'running=', running, 'state=', state);

        // 主页指示灯（统一缓存渲染）
        if (!enabled) {
          dashSetItem('self-protection', '自我保护', 'red', '已关闭');
        } else if (state === 'uninitialized' || state === 'starting') {
          dashSetItem('self-protection', '自我保护', 'yellow', '启动中...');
        } else if (running) {
          dashSetItem('self-protection', '自我保护', 'green', '已启用');
        } else {
          dashSetItem('self-protection', '自我保护', 'gray', '已停止');
        }
      } catch (e) {
        console.warn('applySelfProtectionStatus failed:', e);
      }
    }

    function applyMbrProtectionStatus(status) {
      try {
        if (!status || typeof status !== 'object') return;
        // 缓存状态供 updateDashboardBadge 使用
        window.pslsMbrState = {
          is_running: !!status.is_running,
          is_enabled: status.is_enabled !== false,
          driver_mon_enabled: !!status.driver_mon_enabled,
        };

        var isRunning = window.pslsMbrState.is_running;
        var isEnabled = window.pslsMbrState.is_enabled;
        var driverOk = window.pslsMbrState.driver_mon_enabled;

        if (!isEnabled || !isRunning) {
          // 被用户关闭 / 未运行
          dashSetItem('mbr-protection', 'MBR/关键目录保护', 'red', '未运行');
        } else if (driverOk) {
          // 内核事前拦截 + 用户态轮询
          dashSetItem('mbr-protection', 'MBR/关键目录保护', 'green', '已启用');
        } else {
          // 用户态降级：仅 1 秒轮询 + 事后回滚，事前拦截缺失
          dashSetItem('mbr-protection', 'MBR/关键目录保护', 'yellow', '降级中');
        }
        // 刷新盾牌图标（实时 → 降级 等场景）
        if (document.getElementById('dashboard-shield')) updateDashboardBadge();
      } catch (e) {
        console.warn('applyMbrProtectionStatus failed:', e);
      }
    }

    function applyYaraStatus(status) {
      try {
        if (!status || typeof status !== 'object') return;
        console.log('[APPLY YARA]', status);
        var yaraEnabled = !!status.yara_enabled;
        var yaraInstalled = !!(
          status.yara_installed ||
          status.yara_available ||
          status.yara_direct ||
          status.yara_portable
        );

        // 主页指示灯（使用统一颜色）
        var installBtn = document.getElementById('btn-install-yara');
        if (yaraEnabled && yaraInstalled) {
          dashSetItem('yara', 'YARA 引擎', 'green', '已启用');
        } else if (yaraInstalled && !yaraEnabled) {
          dashSetItem('yara', 'YARA 引擎', 'yellow', '已禁用');
        } else {
          dashSetItem('yara', 'YARA 引擎', 'gray', '未检测');
        }
        if (installBtn) {
          if (yaraInstalled) {
            installBtn.classList.add('hidden');
          } else {
            installBtn.classList.remove('hidden');
            if (window.lucide) lucide.createIcons();
          }
        }

        // 设置页开关和标签
        var yaraToggle = document.getElementById('set-yara');
        var yaraLabel = document.getElementById('set-yara-status-label');
        if (yaraToggle) {
          yaraToggle.checked = yaraEnabled;
          applyToggleState(yaraToggle.closest('.psls-toggle'), yaraEnabled);
          if (!yaraInstalled) {
            yaraToggle.disabled = true;
            yaraToggle.closest('.psls-toggle').style.opacity = '0.4';
            yaraToggle.closest('.psls-toggle').style.pointerEvents = 'none';
          } else {
            yaraToggle.disabled = false;
            yaraToggle.closest('.psls-toggle').style.opacity = '';
            yaraToggle.closest('.psls-toggle').style.pointerEvents = '';
          }
        }
        if (yaraLabel) {
          if (yaraInstalled && yaraEnabled) {
            yaraLabel.style.color = 'var(--psls-c-success-text)';
            yaraLabel.textContent = '已启用';
          } else if (yaraInstalled && !yaraEnabled) {
            yaraLabel.style.color = 'var(--psls-c-warn-text)';
            yaraLabel.textContent = '已禁用';
          } else {
            yaraLabel.style.color = 'var(--psls-c-danger-text)';
            yaraLabel.textContent = '未安装';
          }
        }
      } catch (e) {
        console.warn('applyYaraStatus failed:', e);
      }
    }

    function applyMlStatus(status) {
      try {
        if (!status || typeof status !== 'object') return;
        console.log('[APPLY ML]', status);
        var mlEnabled = !!status.ml_enabled;
        var mlAvailable = !!status.ml_available;
        var onnxInstalled = !!status.ml_onnx_installed;
        var modelLoaded = !!status.ml_model_loaded;

        // 主页指示灯（统一缓存渲染）
        // 绿色：模型已加载且用户启用
        // 红色：引擎可用但全部关闭（ONNX 禁用且 LightGBM 未在运行）
        // 黄色：模型关闭但 LightGBM 补充引擎仍在运行（部分关闭）
        // 灰色：未检测（onnxruntime 未安装 / 模型缺失 且无 LightGBM 补充引擎）
        var btExeExists2 = !!status.brewtotal_exe_exists;
        var btEnabled2 = !!status.brewtotal_enabled;
        var btAvailable2 = !!status.brewtotal_available;
        if (modelLoaded && mlEnabled) {
          dashSetItem('ml', 'ML 引擎', 'green', '已启用');
        } else if (modelLoaded && !mlEnabled && btEnabled2 && btAvailable2) {
          dashSetItem('ml', 'ML 引擎', 'yellow', 'LightGBM 运行中');
        } else if (!modelLoaded && !btExeExists2) {
          dashSetItem('ml', 'ML 引擎', 'gray', '未检测');
        } else if (!onnxInstalled && !btExeExists2) {
          dashSetItem('ml', 'ML 引擎', 'gray', '未检测');
        } else {
          dashSetItem('ml', 'ML 引擎', 'red', '已关闭');
        }

        // 主页一键安装按钮：模型未加载时显示
        var mlInstallBtn = document.getElementById('btn-install-ml');
        if (mlInstallBtn) {
          if (modelLoaded) {
            mlInstallBtn.classList.add('hidden');
          } else {
            mlInstallBtn.classList.remove('hidden');
            if (window.lucide) lucide.createIcons();
          }
        }

        // 设置页开关和标签
        var mlToggle = document.getElementById('set-ml');
        var mlLabel = document.getElementById('set-ml-status-label');
        if (mlToggle) {
          mlToggle.checked = mlEnabled;
          applyToggleState(mlToggle.closest('.psls-toggle'), mlEnabled);
          if (!modelLoaded) {
            mlToggle.disabled = true;
            mlToggle.closest('.psls-toggle').style.opacity = '0.4';
            mlToggle.closest('.psls-toggle').style.pointerEvents = 'none';
          } else {
            mlToggle.disabled = false;
            mlToggle.closest('.psls-toggle').style.opacity = '';
            mlToggle.closest('.psls-toggle').style.pointerEvents = '';
          }
        }
        if (mlLabel) {
          if (modelLoaded && mlEnabled) {
            mlLabel.style.color = 'var(--psls-c-success-text)';
            mlLabel.textContent = '已启用';
          } else if (modelLoaded && !mlEnabled) {
            mlLabel.style.color = 'var(--psls-c-warn-text)';
            mlLabel.textContent = '已禁用';
          } else if (!onnxInstalled) {
            mlLabel.style.color = 'var(--psls-c-danger-text)';
            mlLabel.textContent = '未安装';
          } else {
            mlLabel.style.color = 'var(--psls-c-gray-text)';
            mlLabel.textContent = '无模型';
          }
        }

        // LightGBM 补充引擎开关和标签
        var btEnabled = !!status.brewtotal_enabled;
        var btAvailable = !!status.brewtotal_available;
        var btExeExists = !!status.brewtotal_exe_exists;
        var btToggle = document.getElementById('set-lightgbm');
        var btLabel = document.getElementById('set-lightgbm-status-label');
        if (btToggle) {
          btToggle.checked = btEnabled;
          applyToggleState(btToggle.closest('.psls-toggle'), btEnabled);
          if (!btExeExists) {
            btToggle.disabled = true;
            btToggle.closest('.psls-toggle').style.opacity = '0.4';
            btToggle.closest('.psls-toggle').style.pointerEvents = 'none';
          } else {
            btToggle.disabled = false;
            btToggle.closest('.psls-toggle').style.opacity = '';
            btToggle.closest('.psls-toggle').style.pointerEvents = '';
          }
        }
        if (btLabel) {
          if (!btExeExists) {
            btLabel.style.color = 'var(--psls-c-gray-text)';
            btLabel.textContent = '未安装';
          } else if (btEnabled && btAvailable) {
            btLabel.style.color = 'var(--psls-c-success-text)';
            btLabel.textContent = '已启用';
          } else if (btEnabled && !btAvailable) {
            btLabel.style.color = 'var(--psls-c-danger-text)';
            btLabel.textContent = '不可用';
          } else {
            btLabel.style.color = 'var(--psls-c-warn-text)';
            btLabel.textContent = '已禁用';
          }
        }
      } catch (e) {
        console.warn('applyMlStatus failed:', e);
      }
    }

    function applyStrictModeStatus(status) {
      try {
        if (!status || typeof status !== 'object') return;
        var enabled = !!status.enabled;
        console.log('[APPLY STRICT] enabled=', enabled);

        var toggle = document.getElementById('set-strict-mode');
        var label = document.getElementById('set-strict-mode-label');
        if (toggle && !toggle.disabled) {
          _strictModeSyncing = true;
          toggle.checked = enabled;
          applyToggleState(toggle.closest('.psls-toggle'), enabled);
          _strictModeSyncing = false;
        }
        if (label) {
          label.textContent = enabled ? '已启用' : '已关闭';
          label.style.color = enabled ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
        }
        // 严格模式关闭时，同步更新"监测全部类型"开关为可关闭状态
        if (!enabled) {
          var matToggle = document.getElementById('set-monitor-all-types');
          var matLabel = document.getElementById('set-monitor-all-types-label');
          if (matToggle) {
            matToggle.disabled = false;
            matToggle.style.cursor = 'pointer';
          }
        }
      } catch (e) {
        console.warn('applyStrictModeStatus failed:', e);
      }
    }

    // 应用 VirusIdentifier 开关状态（后端 virusIdentifierStatusChanged 推送）
    // 说明：程序化赋值 toggle.checked 不触发 change 事件，故无需 _syncing 守卫。
    function applyVirusIdentifierStatus(status) {
      try {
        if (!status || typeof status !== 'object') return;
        var enabled = !!status.enabled;
        console.log('[APPLY VI] enabled=', enabled);

        var toggle = document.getElementById('set-virus-identifier');
        var label = document.getElementById('set-virus-identifier-label');
        if (toggle && !toggle.disabled) {
          toggle.checked = enabled;
          applyToggleState(toggle.closest('.psls-toggle'), enabled);
        }
        if (label) {
          label.textContent = enabled ? '已启用' : '已关闭';
          label.style.color = enabled ? 'var(--psls-c-danger-text)' : 'var(--psls-c-gray-text)';
        }
        try { localStorage.setItem('psls:virus-identifier', enabled ? '1' : '0'); } catch (e) {}
      } catch (e) {
        console.warn('applyVirusIdentifierStatus failed:', e);
      }
    }

    // ===== 调试选项面板（设置 → 关于 → 调试选项）=====
    // 两套入口页（米色 index.html / 终端 terminal.html）共用本函数：
    // 按后端 getDebugPopups() 返回的清单渲染按钮，点击后调用
    // pyBridge.debugTriggerPopup(kind) 直接弹出对应窗口，便于后续测试。
    // 只有页面上存在调试容器（#debug-panel）时才生效。
    function _resolveBridgeValue(raw, cb) {
      // QWebChannel 对带返回值的槽，可能给同步值，也可能给 thenable，这里统一处理
      try {
        if (raw && typeof raw.then === 'function') {
          raw.then(function (v) { cb(v); })['catch'](function () { cb(null); });
          return;
        }
      } catch (e) { /* 落到同步分支 */ }
      cb(raw);
    }

    function _parseKinds(raw) {
      if (raw && typeof raw === 'string') {
        try { return JSON.parse(raw); } catch (e) { return null; }
      }
      return raw && raw.length ? raw : null;
    }

    function triggerDebugPopup(kind) {
      var resultEl = document.getElementById('debug-popup-result');
      if (!pyBridge || !pyBridge.debugTriggerPopup) {
        if (resultEl) resultEl.textContent = '桥接未就绪，无法触发';
        return;
      }
      if (resultEl) resultEl.textContent = '正在触发 ' + kind + ' …';
      _resolveBridgeValue(pyBridge.debugTriggerPopup(kind), function (raw) {
        var res = raw;
        if (typeof raw === 'string') {
          try { res = JSON.parse(raw); } catch (e) { res = null; }
        }
        if (resultEl) {
          resultEl.textContent = (res && res.message) || ('已触发 ' + kind);
        }
      });
    }

    function renderDebugButtons(kinds) {
      var listEl = document.getElementById('debug-popup-list');
      if (!listEl) return;
      listEl.innerHTML = '';
      kinds.forEach(function (it) {
        var b = document.createElement('button');
        b.className = 'psls-btn';
        b.setAttribute('data-debug-kind', it.kind);
        b.textContent = it.label || it.kind;
        b.style.cssText = 'font-size:12px;padding:5px 10px;cursor:pointer;';
        b.addEventListener('click', function () { triggerDebugPopup(it.kind); });
        listEl.appendChild(b);
      });
    }

    function pullDebugPopups() {
      var listEl = document.getElementById('debug-popup-list');
      if (!listEl || listEl.childElementCount) return;
      if (!pyBridge || !pyBridge.getDebugPopups) return;
      _resolveBridgeValue(pyBridge.getDebugPopups(), function (raw) {
        var kinds = _parseKinds(raw);
        if (kinds && kinds.length) renderDebugButtons(kinds);
      });
    }

    function initDebugPanel() {
      var panel = document.getElementById('debug-panel');
      var toggle = document.getElementById('btn-debug-toggle');
      if (!panel || !toggle) return;
      if (!toggle.getAttribute('data-debug-bound')) {
        toggle.setAttribute('data-debug-bound', '1');
        toggle.addEventListener('click', function () {
          var open = panel.style.display !== 'none';
          panel.style.display = open ? 'none' : 'block';
          toggle.textContent = open ? '调试选项 ▾' : '调试选项 ▴';
          if (!open) pullDebugPopups();
        });
      }
      pullDebugPopups();
    }

    // ===== Init on DOMContentLoaded =====
    document.addEventListener('DOMContentLoaded', function() {
      if (window.lucide) lucide.createIcons();
      initAllToggles();
      initProtectModules();
      initScanButtons();
      initToolButtons();
      initToolSubpages();
      initDashboardButtons();
      initSettingsButtons();
      initDebugPanel();
      updateDashboardBadge();
      refreshDashboardPanel();
      initBridge();
      // Cross-tab sync
      window.addEventListener('storage', function(e) {
        if (e.key === PROTECT_STORAGE_KEY) {
          refreshProtectUI();
          updateDashboardBadge();
        }
      });
      // 启动时状态同步完全依赖 Python 主动推送（信号机制）
      // 不再使用 JS 端轮询，避免轮询返回错误状态覆盖正确状态
    });
  