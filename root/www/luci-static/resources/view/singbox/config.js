'use strict';
'import fs';
'import view';
'import form';
'import uci';

return L.view.extend({
    handleSaveApply: null,
    handleSave: null,
    handleReset: null,
    lastSwitchTime: 0, // 核心：手動切換時間戳鎖，用來解決後台非同步寫入的時間差

    // --- 輔助：強健的 Base64 解碼 (處理各種訂閱與節點編碼) ---
    safeB64Decode: function(str) {
        if (!str) return "";
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) str += '=';
        try {
            return decodeURIComponent(escape(window.atob(str)));
        } catch (e) {
            try {
                return window.atob(str);
            } catch(e2) {
                return "";
            }
        }
    },

    // --- 核心 1：全協議節點解析器 (增強版) ---
    parseNodeLink: function(link) {
        if (!link || link.trim() === "") return null;
        link = link.trim();
        
        try {
            var protocolMatch = link.match(/^([a-zA-Z0-9]+):\/\/(.*)$/);
            if (!protocolMatch) throw new Error("無法識別的協議格式");
            
            var protocol = protocolMatch[1].toLowerCase();
            var rawContent = protocolMatch[2];
            var node = null;

            if (protocol === 'vmess') {
                var vmessJson = JSON.parse(this.safeB64Decode(rawContent));
                node = {
                    type: "vmess",
                    tag: vmessJson.ps || "VMess-Imported",
                    server: vmessJson.add,
                    server_port: parseInt(vmessJson.port),
                    uuid: vmessJson.id,
                    alter_id: parseInt(vmessJson.aid) || 0,
                    security: vmessJson.scy || "auto"
                };
                if (vmessJson.net === 'ws') {
                    node.transport = { type: "ws", path: vmessJson.path || "/", headers: { Host: vmessJson.host || vmessJson.add } };
                }
                if (vmessJson.tls === 'tls') {
                    node.tls = { enabled: true, server_name: vmessJson.sni || vmessJson.host || vmessJson.add };
                }
                return node;
            }

            var name = "Imported-Node";
            var parts = rawContent.split('#');
            if (parts.length > 1) {
                name = decodeURIComponent(parts.pop());
                rawContent = parts.join('#');
            }

            var query = {};
            var mainUrl = rawContent;
            if (rawContent.indexOf('?') !== -1) {
                var qParts = rawContent.split('?');
                mainUrl = qParts[0];
                qParts[1].split('&').forEach(function(item) {
                    var kv = item.split('=');
                    if (kv.length === 2) query[kv[0]] = decodeURIComponent(kv[1]);
                });
            }

            if (['vless', 'trojan', 'hysteria2'].indexOf(protocol) !== -1) {
                var authAddr = mainUrl.split('@');
                var uuidOrPwd = authAddr[0];
                
                // 健壮分离 host 和未处理的原始端口字符串
                var remainAddr = authAddr[1];
                var firstColonIdx = remainAddr.indexOf(':');
                var host = (firstColonIdx !== -1) ? remainAddr.substring(0, firstColonIdx) : remainAddr;
                var rawPortStr = (firstColonIdx !== -1) ? remainAddr.substring(firstColonIdx + 1) : "";

                node = { type: protocol, tag: name, server: host };
                if (protocol === 'trojan' || protocol === 'hysteria2') node.password = uuidOrPwd;
                else node.uuid = uuidOrPwd;

                if (protocol === 'vless') {
                    node.packet_encoding = "xudp";
                    if (query.flow) { node.flow = query.flow; }
                }

                // --- 🚀 Hysteria2 端口及跳跃精准解析逻辑（支持链接尾部 mport 参数形式） ---
                var serverPortsArray = [];
                var mainPort = null;

                // 1. 首选解析链接自带的主端口
                if (rawPortStr) {
                    var portParts = rawPortStr.split(',');
                    for (var p = 0; p < portParts.length; p++) {
                        var part = portParts[p].trim();
                        if (!part) continue;
                        if (part.indexOf('-') !== -1) {
                            serverPortsArray.push(part.replace('-', ':'));
                        } else {
                            if (!mainPort) mainPort = parseInt(part);
                            else serverPortsArray.push(part);
                        }
                    }
                }

                // 2. 核心修复：针对你提供的 &mport=32000-35000 参数进行补强提取
                var rawMport = query.mport || query.mports || "";
                if (protocol === 'hysteria2' && rawMport) {
                    var mportParts = rawMport.split(',');
                    for (var m = 0; m < mportParts.length; m++) {
                        var mPart = mportParts[m].trim();
                        if (!mPart) continue;
                        if (mPart.indexOf('-') !== -1) {
                            serverPortsArray.push(mPart.replace('-', ':'));
                        } else {
                            serverPortsArray.push(mPart);
                        }
                    }
                }

                // 3. 按照你要求的标准结构落盘生成 JSON (已成功补全 Hysteria2 上下载带宽参数)
                node["server_port"] = mainPort || 443;
                if (protocol === 'hysteria2') {
                    node["up_mbps"] = parseInt(query.up_mbps || query.up) || 50;
                    node["down_mbps"] = parseInt(query.down_mbps || query.down) || 50;
                    if (serverPortsArray.length > 0) {
                        node["server_ports"] = serverPortsArray;
                        node["hop_interval"] = "30s";
                    }
                }

                if (query.security === 'tls' || query.security === 'reality' || protocol === 'hysteria2' || protocol === 'trojan') {
                    node.tls = { enabled: true, server_name: query.sni || query.peer || host, insecure: (query.allowInsecure === '1' || query.insecure === '1') };
                    if (query.alpn) { node.tls.alpn = query.alpn.split(','); }
                    if (query.fp) { node.tls.utls = { enabled: true, fingerprint: query.fp }; }
                    else if (query.security === 'reality') { node.tls.utls = { enabled: true, fingerprint: "chrome" }; }
                    if (query.security === 'reality') { node.tls.reality = { enabled: true, public_key: query.pbk, short_id: query.sid || "" }; }
                }
                return node;
            }

            if (protocol === 'ss') {
                var ssHostPort, ssMethodPwd;
                if (mainUrl.indexOf('@') !== -1) {
                    var ssParts = mainUrl.split('@');
                    ssMethodPwd = this.safeB64Decode(ssParts[0]).split(':');
                    ssHostPort = ssParts[1].split(':');
                } else {
                    var decodedMain = this.safeB64Decode(mainUrl);
                    var ssParts2 = decodedMain.split('@');
                    ssMethodPwd = ssParts2[0].split(':');
                    ssHostPort = ssParts2[1].split(':');
                }
                node = { type: "shadowsocks", tag: name, server: ssHostPort[0], server_port: parseInt(ssHostPort[1]), method: ssMethodPwd[0], password: ssMethodPwd[1] };
                return node;
            }
            throw new Error("暫不支持該協議: " + protocol);
        } catch (e) {
            console.error("解析錯誤:", e);
            return null;
        }
    },

    // --- 核心 2：統一編輯器 ---
    openEditor: function(filename, initialContent, confdir) {
        var isNew = !filename;
        var currentName = filename || '';
        var content = initialContent || '{\n  "outbounds": []\n}';
        var linkInput = E('input', { 
            'class': 'cbi-input-text', 
            'style': 'flex:1; border: 2px dashed #46a546; background: #f9fff9; padding: 10px;', 
            'placeholder': _('⚡ 點擊此處粘貼節點鏈接 (Vmess/Vless/Trojan/SS/Hy2) ，將自動生成並覆蓋當前配置...') 
        });
        var nameInput = E('input', { 'class': 'cbi-input-text', 'style': 'width:250px; font-weight:bold; color:#46a546;', 'placeholder': _('文件名 (如: HK-01.json)'), 'value': currentName });
        var linesContainer = E('div', { 'style': 'width:40px; text-align:right; padding:10px 5px; background:#f5f5f5; color:#999; font-family:monospace; font-size:13px; overflow:hidden; border-right:1px solid #ccc; user-select:none;' }, '1');
        var ta = E('textarea', { 'style': 'flex:1; width:100%; min-height:250px; max-height:50vh; font-family:monospace; font-size:13px; padding:10px; box-sizing:border-box; border:none; outline:none; white-space:pre; overflow-x:auto; resize:vertical;' }, [ content ]);
        var updateLineNumbers = function() {
            var lines = ta.value.split('\n').length + 5;
            var html = '';
            for(var i = 1; i <= lines; i++) html += i + '<br>';
            linesContainer.innerHTML = html;
        };
        ta.addEventListener('scroll', function() { linesContainer.scrollTop = ta.scrollTop; });
        ta.addEventListener('input', updateLineNumbers);
        setTimeout(updateLineNumbers, 50);
        linkInput.addEventListener('input', L.bind(function(e) {
            var val = e.target.value.trim();
            if (!val || !/^[a-zA-Z0-9]+:\/\//.test(val)) return;

            var node = this.parseNodeLink(val);
            if (node) {
                if (isNew && !nameInput.value.trim()) {
                    var safeName = (node.tag || 'Imported-Node').replace(/[^a-zA-Z0-9_\-\u4e00-\u9fa5]/g, '_');
                    nameInput.value = safeName + '.json';
                }

                var standardConfig = {
                    "log": { "level": "info", "timestamp": true },
                    "inbounds": [ { "type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": 10811, "udp_fragment": true } ],
                    "outbounds": [ node ],
                    "route": {
                        "rules": [ { "inbound": "socks-in", "action": "route", "outbound": node.tag } ],
                        "final": node.tag
                    }
                };
                ta.value = JSON.stringify(standardConfig, null, 4);
                var originalBg = linkInput.style.background;
                linkInput.style.background = '#d4edda';
                setTimeout(function(){ linkInput.style.background = originalBg; }, 300);
                e.target.value = ''; 
                updateLineNumbers();
            }
        }, this));
        L.ui.showModal(isNew ? _('✨ 新建/導入配置') : _('✏️ 編輯配置: ') + filename, [ 
            E('div', { 'style': 'display:flex; margin-bottom:15px; padding-bottom:15px; border-bottom:1px dashed #ccc;' }, [ linkInput ]),
            E('div', { 'style': 'display:flex; align-items:center; gap:10px; margin-bottom:10px;' }, [
                E('label', { 'style': 'font-weight:bold; width:80px;' }, _('文件名稱:')),
                nameInput,
                isNew ? E('span', { 'style': 'color:#999; font-size:0.9em;' }, _('(*粘貼鏈接可自動生成)')) : ''
            ]),
            E('div', { 'style': 'border:1px solid #ccc; display:flex; margin-bottom:15px; max-height:55vh; overflow:hidden; border-radius:4px;' }, [ linesContainer, ta ]),
            E('div', { 'class': 'right', 'style': 'display:flex; gap:10px; align-items:center;' }, [
                E('button', { 'class': 'btn cbi-button-neutral', 
                'click': function() { 
                    try { JSON.parse(ta.value); alert(_('JSON 格式正確 ✔'));
                } catch(e) { alert(_('語法錯誤: ') + e.message); }
                }}, _('檢查語法')),
                E('button', { 'class': 'btn cbi-button-neutral', 'click': function() { 
                    try { var obj = JSON.parse(ta.value); ta.value = JSON.stringify(obj, null, 4); updateLineNumbers(); } 
                    catch(e) { alert(_('格式化失敗，請先檢查語法')); }
                }}, _('格式化')),
                E('div', { 'style': 'flex-grow:1;' }), 
                E('button', { 'class': 'btn', 'click': L.ui.hideModal }, _('取消')),
                E('button', { 'class': 'btn cbi-button-positive', 'click': L.bind(function() { 
                    var finalName = nameInput.value.trim();
                    if (!finalName) { alert(_('請輸入文件名稱！')); return; }
                    if (!finalName.endsWith('.json')) finalName += '.json';

                    try {
                        var obj = JSON.parse(ta.value);
                        var stringifyContent = JSON.stringify(obj, null, 4);

                        L.fs.write(confdir + '/' + finalName, stringifyContent).then(L.bind(function() {
                            var currentActiveName = null;
                            var activeRow = document.querySelector('tr[data-filename] .check-cell span');
                            if (activeRow) {
                                var rowTr = activeRow.closest('tr');
                                if (rowTr) currentActiveName = rowTr.getAttribute('data-filename');
                            }
                            if (!currentActiveName) { currentActiveName = L.uci.get('sing-box', 'main', 'selected_conf'); }

                            if (finalName === currentActiveName) {
                                return L.fs.write(confdir + '/config.json', stringifyContent).then(L.bind(function() {
                                    return this.doRestart(); 
                                }, this)).then(L.bind(function() {
                                    window.sessionStorage.removeItem('sb_net_cache'); 
                                    setTimeout(L.bind(this.checkNetwork, this, true), 1000); 
                                    alert(_('當前生效配置已同步寫入主配置，服務已完成自動重啟重載！'));
                                }, this));
                            } else {
                                alert(_('配置儲存成功（非當前生效節點，未觸發重載）。'));
                            }
                        }, this)).then(L.bind(function() {
                            L.ui.hideModal(); 
                            var container = document.getElementById('sb_file_list_container');
                            if (container) this.renderList(container, confdir, L.uci.get('sing-box', 'main', 'selected_conf'));
                        }, this)).catch(function(err) {
                            alert(_('儲存或同步重載失敗: ') + (err.message || err));
                        });
                    } catch(e) { alert(_('JSON 錯誤，無法儲存: \n') + e.message); }
                }, this) }, _('儲存配置'))
            ])
        ]);
    },

    // --- 🚀 新增功能：批量訂閱導入彈窗與解析落盤 ---
    openSubscriptionImporter: function(confdir) {
        var subInput = E('input', {
            'class': 'cbi-input-text',
            'style': 'flex:1; padding: 10px; border: 2px dashed #007bff; background: #f0f7ff;',
            'placeholder': _('🔗 請在此粘貼機場訂閱鏈接 (HTTP/HTTPS) ...')
        });
        L.ui.showModal(_('🚀 批量訂閱導入'), [
            E('div', { 'style': 'display:flex; flex-direction:column; gap:15px; min-width:500px;' }, [
                E('div', { 'style': 'display:flex;' }, [ subInput ]),
                E('div', { 'style': 'color:#666; font-size:0.95em; line-height:1.5;' }, [
                    _('說明：粘貼完整的訂閱鏈接後點擊導入，系統會自動下載並解析其中包含的 Vmess / Vless / Trojan / Shadowsocks / Hysteria2 節點，並在指定目錄批量生成獨立配置。')
                ]),
                E('div', { 'class': 'right', 'style': 'display:flex; gap:10px; justify-content:flex-end; margin-top:10px;' }, [
                    E('button', { 'class': 'btn', 'click': L.ui.hideModal }, _('取消')),
                    E('button', {
                        'class': 'btn cbi-button-positive',
                        'style': 'background:#007bff !important;',
                        'click': L.bind(function(ev) {
                            var url = subInput.value.trim();
                            if (!url || !/^https?:\/\//i.test(url)) {
                                alert(_('請輸入有效的 HTTP/HTTPS 訂閱鏈接！'));
                                return;
                            }

                            var btn = ev.target;
                            btn.disabled = true;
                            btn.textContent = _('正在下載並解析...');

                            // 使用 /bin/sh -c 包装 curl 下载，绕过浏览器跨域和 LuCI 权限限制
                            L.fs.exec('/bin/sh', ['-c', 'curl -s -L -k --connect-timeout 15 "' + url.replace(/"/g, '\\"') + '"'])
                            .then(function(res) {
                                if (res.code !== 0) throw new Error(_('網絡獲取訂閱失敗，請檢查路由器連通性。'));
                                return res.stdout;
                            })
                            .then(L.bind(function(rawBody) {
                                if (!rawBody || rawBody.trim() === "") throw new Error(_('訂閱內容為空'));
                                
                                var decodedContent = this.safeB64Decode(rawBody.trim());
                                if (!decodedContent || decodedContent.trim() === "") {
                                    decodedContent = rawBody; 
                                }

                                var lines = decodedContent.split(/[\r\n]+/);
                                var validNodes = [];
                                
                                for (var i = 0; i < lines.length; i++) {
                                    var line = lines[i].trim();
                                    if (!line || !/^[a-zA-Z0-9]+:\/\//.test(line)) continue;
                                    
                                    var nodeObj = this.parseNodeLink(line);
                                    if (nodeObj) {
                                        validNodes.push(nodeObj);
                                    }
                                }

                                if (validNodes.length === 0) {
                                    throw new Error(_('訂閱中未探測到受支持的有效節點鏈接！'));
                                }

                                var writePromises = [];
                                var nameCounter = {};

                                validNodes.forEach(L.bind(function(node) {
                                    var baseName = (node.tag || 'Imported-Node').replace(/[^a-zA-Z0-9_\-\u4e00-\u9fa5]/g, '_');
                                    
                                    if (!nameCounter[baseName]) {
                                        nameCounter[baseName] = 1;
                                    } else {
                                        nameCounter[baseName]++;
                                        baseName += '_' + nameCounter[baseName];
                                    }

                                    var finalFileName = baseName + '.json';

                                    var standardConfig = {
                                        "log": { "level": "info", "timestamp": true },
                                        "inbounds": [ { "type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": 10811, "udp_fragment": true } ],
                                        "outbounds": [ node ],
                                        "route": {
                                            "rules": [ { "inbound": "socks-in", "action": "route", "outbound": node.tag } ],
                                            "final": node.tag
                                        }
                                    };
                                    var task = L.fs.write(confdir + '/' + finalFileName, JSON.stringify(standardConfig, null, 4));
                                    writePromises.push(task);
                                }, this));

                                return Promise.all(writePromises).then(L.bind(function() {
                                    alert(_('🎉 成功批量導入 ') + validNodes.length + _(' 個節點配置檔案！'));
                                    L.ui.hideModal();
                                    
                                    var container = document.getElementById('sb_file_list_container');
                                    if (container) {
                                        this.renderList(container, confdir, L.uci.get('sing-box', 'main', 'selected_conf'));
                                    }
                                }, this));

                            }, this))
                            .catch(function(err) {
                                btn.disabled = false;
                                btn.textContent = _('確認導入');
                                alert(_('導入失敗: ') + (err.message || err));
                            });
                        }, this)
                    }, _('確認導入'))
                ])
            ])
        ]);
    },

    getCache: function() { return window.sessionStorage.getItem('sb_net_cache'); },
    setCache: function(val) { window.sessionStorage.setItem('sb_net_cache', val); },

    load: function() {
        return Promise.all([
            L.uci.load('sing-box'),
            L.fs.exec('/etc/init.d/sing-box', ['status']).then(function(res) { return (res.code === 0); }).catch(function() { return false; })
        ]);
    },

    checkNetwork: function(isExplicit) {
        var netDot = document.getElementById('sb_net_dot');
        var netText = document.getElementById('sb_net_text');
        if (!netDot || !netText) return;

        if (isExplicit) {
            netText.textContent = _('連通性測試中...');
            netDot.style.background = '#17a2b8'; 
        }

        var cmdCn = 'curl -I -s --connect-timeout 2 http://223.5.5.5 >/dev/null 2>&1 && exit 0 || exit 1';
        var cmdGlobal = 'curl -I -s --connect-timeout 2 http://www.google.com/generate_204 >/dev/null 2>&1 && exit 0 || exit 1';
        Promise.all([
            L.fs.exec('/bin/sh', ['-c', cmdCn]).catch(function() { return { code: 1 }; }),
            L.fs.exec('/bin/sh', ['-c', cmdGlobal]).catch(function() { return { code: 1 }; })
        ]).then(L.bind(function(results) {
            var cnOK = (results[0] && results[0].code === 0);
            var globalOK = (results[1] && results[1].code === 0);
            
            var state, text, color;
            if (cnOK && globalOK) { state = 'all_ok'; text = _('海內外暢通'); color = '#46a546'; } 
            else if (cnOK && !globalOK) { state = 'cn_only'; text = _('僅國內連通'); color = '#ffc107'; } 
            else if (!cnOK && globalOK) { state = 'global_only'; text = _('僅國外連通'); color = '#6f42c1'; } 
            else { state = 'offline'; text = _('網路已斷開'); color = '#dc3545'; }

            if (this.getCache() !== state || isExplicit) {
                netText.textContent = text;
                netDot.style.background = color;
                this.setCache(state);
            }
        }, this)).catch(function() {
            if (netText && netDot) { netText.textContent = _('狀態未知'); netDot.style.background = '#999'; }
        });
    },

    checkStatus: function(confdir) {
        return L.fs.exec('/etc/init.d/sing-box', ['status']).then(L.bind(function(res) {
            var isRunning = (res.code === 0);
            var sDot = document.getElementById('sb_status_dot');
            var sText = document.getElementById('sb_status_text');
            if (sDot && sText) {
                sText.textContent = isRunning ? _('運行中') : _('已停止');
                sDot.style.background = isRunning ? '#46a546' : '#999';
            }
            this.checkNetwork(false);

            if (this.lastSwitchTime && (Date.now() - this.lastSwitchTime < 3000)) {
                return;
            }

            if (confdir) {
                L.fs.read(confdir + '/config.json').then(L.bind(function(configContent) {
                    if (!configContent) return;
                    var activeOutboundsStr = "";
                    try {
                        var configJson = JSON.parse(configContent);
                        if (configJson.outbounds) activeOutboundsStr = JSON.stringify(configJson.outbounds);
                    } catch(e) { return; }

                    if (!activeOutboundsStr) return;
                    var rows = document.querySelectorAll('tr[data-filename]');
                    rows.forEach(function(row) {
                        var rowOutbounds = row.getAttribute('data-outbounds');
                        var cCell = row.querySelector('.check-cell');
                        var nCell = row.querySelector('.name-cell');
                        var aBtn = row.querySelector('.cbi-button-apply');

                        if (rowOutbounds && rowOutbounds === activeOutboundsStr) {
                            if (cCell && !cCell.innerHTML.includes('✔')) cCell.innerHTML = '<span style="color:#46a546; font-weight:bold; font-size:1.2em;">✔</span>';
                            if (nCell && nCell.style.color !== 'rgb(70, 165, 70)') { nCell.style.fontWeight = 'bold'; nCell.style.color = '#46a546'; }
                            if (aBtn && aBtn.textContent !== _('生效中')) { aBtn.disabled = false; aBtn.textContent = _('生效中'); }
                        } else if (rowOutbounds) {
                            if (cCell && cCell.innerHTML !== '') cCell.innerHTML = '';
                            if (nCell && (nCell.style.fontWeight === 'bold' || nCell.style.color)) { nCell.style.fontWeight = 'normal'; nCell.style.color = ''; }
                            if (aBtn && aBtn.textContent === _('生效中')) { aBtn.disabled = false; aBtn.textContent = _('選用'); }
                        }
                    });
                }, this)).catch(function(){});
            }
        }, this)).catch(function(){});
    },

    doRestart: function() { return L.fs.exec('/etc/init.d/sing-box', ['restart']); },
    doStop: function() { return L.fs.exec('/etc/init.d/sing-box', ['stop']); },

    handleSwitch: function(filename, confdir, ev) {
        var btn = ev.target;
        if (btn.textContent.trim() === _('生效中')) {
            alert(_('該配置已在生效中，無須重複應用。'));
            return;
        }

        btn.disabled = true;
        btn.textContent = _('正在應用...');
        this.lastSwitchTime = Date.now();
        L.fs.read(confdir + '/' + filename).then(L.bind(function(content) {
            return L.fs.write(confdir + '/config.json', content);
        }, this)).then(L.bind(function() {
            L.uci.set('sing-box', 'main', 'selected_conf', filename);
            return L.uci.save().then(function() { return L.uci.apply(); });
        }, this)).then(L.bind(function() {
            try {
                var indicator = document.getElementById('changes_indicator_config') || document.getElementById('indicators');
                if (indicator) { indicator.style.display = 'none'; indicator.innerHTML = ''; }
                var argonIndicator = document.querySelector('.uci_change_indicator') || document.querySelector('.changes-indicator');
                if (argonIndicator) { argonIndicator.style.display = 'none'; argonIndicator.remove(); }
            } catch(domErr) {
                console.log("消除提示失敗:", domErr); 
            }

            return this.doRestart().catch(function() { throw new Error(_('重啟服務失敗')); });
        }, this)).then(L.bind(function() {
            var rows = document.querySelectorAll('tr[data-filename]');
            rows.forEach(function(row) {
                var f = row.getAttribute('data-filename');
                var cCell = row.querySelector('.check-cell');
                var nCell = row.querySelector('.name-cell');
                var aBtn = row.querySelector('.cbi-button-apply');
                if (f === filename) {
                    if (cCell) cCell.innerHTML = '<span style="color:#46a546; font-weight:bold; font-size:1.2em;">✔</span>';
                    if (nCell) { nCell.style.fontWeight = 'bold'; nCell.style.color = '#46a546'; }
                    if (aBtn) { aBtn.disabled = false; aBtn.textContent = _('生效中'); }
                } else {
                    if (cCell) cCell.innerHTML = '';
                    if (nCell) { nCell.style.fontWeight = 'normal'; nCell.style.color = ''; }
                    if (aBtn) { aBtn.disabled = false; aBtn.textContent = _('選用'); }
                }
            });
            window.sessionStorage.removeItem('sb_net_cache');
            this.checkNetwork(true);

            setTimeout(L.bind(function() {
                var container = document.getElementById('sb_file_list_container');
                if (container) { this.renderList(container, confdir, filename); }
            }, this), 3500);
        }, this)).catch(function(e) {
            btn.disabled = false; btn.textContent = _('選用');
            alert(e.message || _('操作失敗，請檢查權限')); 
        });
    },

    renderList: function(container, confdir, selectedConf) {
        return Promise.all([
            L.fs.list(confdir),
            L.fs.read(confdir + '/config.json').catch(function() { return null; })
        ]).then(L.bind(function(results) {
            var files = results[0];
            var configContent = results[1];
            var activeOutboundsStr = "";

            if (configContent) {
                try {
                    var configJson = JSON.parse(configContent);
                    if (configJson.outbounds) { activeOutboundsStr = JSON.stringify(configJson.outbounds); }
                } catch(e) {}
            }

            files.sort(function(a, b) { return (b.mtime || 0) - (a.mtime || 0); });

            var table = E('table', { 'class': 'table cbi-section-table' }, [
                E('tr', { 'class': 'tr cbi-section-table-titles' }, [
                    E('th', { 'class': 'th', 'style': 'width:40px; text-align:center;' }, ''), 
                    E('th', { 'class': 'th', 'style': 'width:auto; font-size:1.05em; font-weight:bold;' }, _('檔案名稱')),
                    E('th', { 'class': 'th', 'style': 'width:120px; font-size:1.05em; font-weight:bold;' }, _('協議')),
                    E('th', { 'class': 'th', 'style': 'width:auto; font-size:1.05em; font-weight:bold;' }, _('域名 / IP')),
                    E('th', { 'class': 'th', 'style': 'width:320px; text-align:center; font-size:1.05em; font-weight:bold;' }, _('管理操作'))
                ])
            ]);
            var rowsMap = {};

            files.forEach(L.bind(function(file) {
                if (file.name.endsWith('.json') && file.name !== 'config.json') {
                    var isSelected = (file.name === selectedConf);
                    
                    var checkCell = E('td', { 'class': 'td check-cell', 'style': 'text-align:center; vertical-align:middle;' }, [ isSelected ? E('span', { 'style': 'color:#46a546; font-weight:bold; font-size:1.2em;' }, '✔') : '' ]);
                    var nameCell = E('td', { 'class': 'td name-cell', 'style': 'vertical-align:middle; font-size:1.05em; ' + (isSelected ? 'font-weight:bold; color:#46a546;' : '') }, file.name);
                    var typeCell = E('td', { 'class': 'td', 'style': 'vertical-align:middle; color:#555; font-size:1.05em; font-weight:bold; text-transform:uppercase; padding-right:15px;' }, _('讀取中...'));
                    var infoCell = E('td', { 'class': 'td', 'style': 'vertical-align:middle; color:#666; font-size:1.05em; word-break:break-word; padding-right:15px;' }, '');
                    var applyBtn = E('button', { 
                        'class': 'cbi-button cbi-button-apply',
                        'style': 'padding:7px 22px; border-radius:100px; background:#46a546 !important; color:#fff !important; border:none; font-size:1.05em; font-weight:500;',
                        'click': L.bind(this.handleSwitch, this, file.name, confdir)
                    }, isSelected ? _('生效中') : _('選用'));
                    rowsMap[file.name] = { checkCell: checkCell, nameCell: nameCell, applyBtn: applyBtn };
                    L.fs.read(confdir + '/' + file.name).then(L.bind(function(res) {
                        if (!res) { typeCell.textContent = '-'; return; }
                        try {
                            var json = JSON.parse(res);
                            var servers = [], types = [];
                            if (json.outbounds && Array.isArray(json.outbounds)) {
                                json.outbounds.forEach(function(out) {
                                    if (out.server && typeof out.server === 'string' && out.server !== '127.0.0.1' && out.server !== '::1') {
                                        servers.push(out.server); if (out.type) types.push(out.type);
                                    }
                                });
                            }
                            typeCell.textContent = types.length > 0 ? types.filter(function(v, i, a) { return a.indexOf(v) === i; }).join(', ') : '-';
                            infoCell.textContent = servers.length > 0 ? servers.filter(function(v, i, a) { return a.indexOf(v) === i; }).join(', ') : '';
                            var rowTr = table.querySelector('tr[data-filename="' + file.name + '"]');
                            if (rowTr && json.outbounds) {
                                rowTr.setAttribute('data-outbounds', JSON.stringify(json.outbounds));
                            }

                            if (activeOutboundsStr && json.outbounds && JSON.stringify(json.outbounds) === activeOutboundsStr) {
                                if (this.lastSwitchTime && (Date.now() - this.lastSwitchTime < 3000)) { return; }

                                Object.keys(rowsMap).forEach(function(k) {
                                    rowsMap[k].checkCell.innerHTML = '';
                                    rowsMap[k].nameCell.style.fontWeight = 'normal';
                                    rowsMap[k].nameCell.style.color = '';
                                    rowsMap[k].applyBtn.textContent = _('選用');
                                });
                                checkCell.innerHTML = '<span style="color:#46a546; font-weight:bold; font-size:1.2em;">✔</span>';
                                nameCell.style.fontWeight = 'bold';
                                nameCell.style.color = '#46a546';
                                applyBtn.textContent = _('生效中');
                            }
                        } catch(e) { 
                            typeCell.textContent = 'JSON 錯誤';
                            typeCell.style.color = '#dc3545'; 
                        }
                    }, this));
                    table.appendChild(E('tr', { 'class': 'tr', 'data-filename': file.name }, [
                        checkCell, nameCell, typeCell, infoCell,
                        E('td', { 'class': 'td', 'style': 'text-align:center; vertical-align:middle; white-space:nowrap; width:320px;' }, [
                            applyBtn,
                            E('button', { 
                                'class': 'cbi-button cbi-button-neutral', 
                                'style': 'margin-left:8px; padding:7px 22px; border-radius:100px; background:#999 !important; color:#fff !important; border:none; font-size:1.05em; font-weight:500;', 
                                'click': L.bind(function() {
                                    L.fs.read(confdir + '/' + file.name).then(L.bind(function(content) { this.openEditor(file.name, content, confdir); }, this)).catch(function(){ alert(_('無法讀取文件')); });
                                }, this) 
                            }, _('編輯')),
                            E('button', { 
                                'class': 'cbi-button cbi-button-remove', 
                                'style': 'margin-left:8px; padding:7px 22px; border-radius:100px; background:#dc3545 !important; color:#fff !important; border:none; font-size:1.05em; font-weight:500;', 
                                'click': L.bind(function(ev) { 
                                    if (confirm(_('確定刪除此配置嗎？'))) {
                                        L.fs.remove(confdir + '/' + file.name).then(L.bind(function(){ ev.target.closest('tr').remove(); }, this)).catch(function(){ alert(_('刪除失敗')); }); 
                                    }
                                }, this) 
                            }, _('刪除'))
                        ])
                    ]));
                }
            }, this));

            container.innerHTML = '';
            container.appendChild(table);
        }, this));
    },

    render: function(data) {
        var isRunning = data[1];
        var confdir = L.uci.get('sing-box', 'main', 'confdir') || '/etc/sing-box';
        var selectedConf = L.uci.get('sing-box', 'main', 'selected_conf');
        var m = new L.form.Map('sing-box', _('Sing-box Bridge'), _('SING-BOX 服務管理'));
        var s = m.section(L.form.TypedSection, '_status', _('服務控制'));
        s.anonymous = true;
        s.render = L.bind(function() {
            if (this.statusTimer) window.clearInterval(this.statusTimer);
            this.statusTimer = window.setInterval(L.bind(this.checkStatus, this, confdir), 5000);

            var cached = this.getCache();
            var labelText = '', labelBg = 'transparent';

            if (cached === 'all_ok') { labelText = _('海內外暢通'); labelBg = '#46a546'; } 
            else if (cached === 'cn_only') { labelText = _('僅國內連通'); labelBg = '#ffc107'; } 
            else if (cached === 'global_only') { labelText = _('僅國外連通'); labelBg = '#6f42c1'; } 
            else if (cached === 'offline') { labelText = _('網路已斷開'); labelBg = '#dc3545'; } 
            else { 
                labelText = _('連通性測試中...'); 
                labelBg = '#17a2b8'; 
                setTimeout(L.bind(this.checkNetwork, this, true), 100); 
            }

            return E('div', { 'class': 'cbi-value', 'style': 'display:flex; flex-direction:column; border-bottom:1px solid #eee; padding-bottom:10px;' }, [
                E('div', { 'style': 'display:flex; align-items:center; width:100%; margin-bottom:10px;' }, [
                    E('label', { 'class': 'cbi-value-title', 'style': 'width:15%' }, _('運行狀態')),
                    E('div', { 'class': 'cbi-value-field', 'style': 'width:85%; display:flex; align-items:center;' }, [
                        E('span', { 'id': 'sb_status_label', 'style': 'display:inline-flex; align-items:center; gap:8px;' }, [
                            E('span', { 'id': 'sb_status_dot', 'style': 'display:inline-block; width:12px; height:12px; border-radius:50%; background:' + (isRunning ? '#46a546' : '#999') + ';' }),
                            E('span', { 'id': 'sb_status_text', 'style': 'font-weight:bold; color:#444;' }, isRunning ? _('運行中') : _('已停止'))
                        ]),
                        E('span', { 'id': 'sb_net_label', 'style': 'display:inline-flex; align-items:center; gap:8px; margin-left:25px;' }, [
                            E('span', { 'id': 'sb_net_dot', 'style': 'display:inline-block; width:12px; height:12px; border-radius:50%; background:' + labelBg + ';' }),
                            E('span', { 'id': 'sb_net_text', 'style': 'font-weight:bold; color:#444;' }, labelText)
                        ]),
                        E('button', { 'class': 'cbi-button', 'style': 'margin-left:auto; padding:6px 20px; border-radius:100px; background:#46a546 !important; color:#fff !important; border:none;', 'click': L.bind(function(ev) {
                            ev.target.textContent = _('正在重啟...'); window.sessionStorage.removeItem('sb_net_cache');
                            return this.doRestart().then(L.bind(function(){ ev.target.textContent = _('重啟 sing-box'); setTimeout(L.bind(this.checkStatus, this, confdir), 1000); }, this));
                        }, this) }, _('重啟 sing-box')),
                        E('button', { 'class': 'cbi-button', 'style': 'margin-left:10px; padding:6px 20px; border-radius:100px; background:#999 !important; color:#fff !important; border:none;', 'click': L.bind(function(ev) {
                            ev.target.textContent = _('正在停止...'); window.sessionStorage.removeItem('sb_net_cache');
                            return this.doStop().then(L.bind(function(){ ev.target.textContent = _('停止 sing-box'); setTimeout(L.bind(this.checkStatus, this, confdir), 600); }, this));
                        }, this) }, _('停止 sing-box')),
                        E('button', { 'class': 'cbi-button cbi-button-add', 'style': 'margin-left:10px; padding:6px 20px; border-radius:100px;', 'click': L.bind(function() { this.openEditor(null, null, confdir); }, this) }, _('⚡ 快速導入 / 新建')),
                        E('button', { 
                            'class': 'cbi-button cbi-button-add', 
                            'style': 'margin-left:10px; padding:6px 20px; border-radius:100px; background:#007bff !important; color:#fff !important; border:none;', 
                            'click': L.bind(function() { this.openSubscriptionImporter(confdir); }, this) 
                        }, _('🔄 訂閱導入'))
                    ])
                ])
            ]);
        }, this);

        var s2 = m.section(L.form.TypedSection, '_list', _('可用配置文件'));
        s2.render = L.bind(function() {
            var container = E('div', { 'id': 'sb_file_list_container' });
            this.renderList(container, confdir, selectedConf);

            // 🚀 核心优化：在列表正下方精准生成三个橙色底部链接，并且用新窗口打开
            var footerLinks = E('div', { 'style': 'margin-top: 25px; padding-top: 15px; border-top: 1px dashed #ddd; display: flex; gap: 25px; justify-content: center; font-size: 0.92em;' }, [
                E('a', { 'href': 'https://dae-rule.bbsok.workers.dev/?ui=true', 'target': '_blank', 'style': 'color: #ff8c00; font-weight: bold; text-decoration: none;' }, _('DAED规则配置')),
                E('a', { 'href': 'https://github.com/bslgw/jddy', 'target': '_blank', 'style': 'color: #ff8c00; font-weight: bold; text-decoration: none;' }, _('简单订阅管理')),
                E('a', { 'href': 'https://github.com/bslgw/my-openwrt-brutal', 'target': '_blank', 'style': 'color: #ff8c00; font-weight: bold; text-decoration: none;' }, _('Brutal'))
            ]);

            return E('div', {}, [ container, footerLinks ]);
        }, this);
        return m.render();
    }
});
