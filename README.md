<img width="1130" height="511" alt="捕1获" src="https://github.com/user-attachments/assets/70f35870-f1eb-4b1a-a828-411900914a62" />
openwrt控制台

---

<img width="1195" height="599" alt="捕获" src="https://github.com/user-attachments/assets/8cc0f937-b981-4849-828e-453b63d45b7b" />


web界面，端口:2025




### luci-app-sing-box-bridge

### 極簡 sing-box 管理界面，旨在作為 daed 外掛 sing-box 時提供高性能节点管理

### 使用場景：

使用獨立的 sing-box 配合 daed 創建的 socket，實現 hy2 的端口跳躍、brutal 等。

### 使用條件：

安裝獨立的 sing-box

在 daed 內配置 socket

修改節點的 json，把 socket 作為節點的流量入口

```
"inbounds": [
    {
      // start
      "type": "socks",
      "tag": "socks-in",
      "listen": "0.0.0.0",
      "listen_port": 10811
      // end
    }
  ]
```




---

### 📌 核心特色

*   **零冗餘**：專注於內核狀態、架構顯示與節點配置編輯。
*   **方案 A 兼容**：完美對接官方 `sing-box` 服務，不破壞系統路徑。
*   **架構透明**：自動顯示 CPU 架構與內核版本，確保運行環境匹配。

---

### 🛠 安裝前的依賴準備 (重要)

為了確保插件運行正常，請先確保系統已安裝以下依賴。若本地軟體包索引過時，請務必先執行 `update`。

```bash
# 更新軟體源
opkg update

# 安裝核心依賴
opkg install curl
```

---

### 🚀 安裝步驟

1. 從 **Releases** 頁面下載對應架構的 `.ipk` 檔案。
2. 使用 WinSCP 或 SCP 將檔案上傳至路由器 `/tmp` 目錄。
3. 執行安裝指令：
   ```bash
   opkg install /tmp/luci-app-sing-box_*.ipk
   ```
4. **若選單未出現**，請清理 LuCI 緩存並刷新頁面：
   ```bash
   rm -rf /tmp/luci-indexcache
   ```

---

### 📖 使用說明

*   **服務開關**：開啟後將啟動官方 `sing-box` 服務進程。
*   **節點配置**：在介面中點擊「編輯」，直接粘貼您的 Outbound JSON 配置。
*   **配合 daed**：在 daed 配置中將核心指向此處管理的實例，即可享受最新版內核特性。



###  相关推荐

*   一个简单的订阅管理功能，将多个节点链接，整合生成一个订阅链接
*   使用worker部署
*   https://github.com/bslgw/jddy



