# Fieldstation 只读工作台

第一版提供本机 HTML 界面，默认使用明确标注的虚构示例数据。切换“实际连接”后，工作台通过服务的公开只读 HTTP 接口读取数据；IM 需要输入已知 Issue ID。工作台不提供写入或岗位启动功能。

使用 Python 3.11+，从源码目录启动：

```powershell
python .\fieldstation_console\server.py
```

也可以在安装本项目构建的 Issue Manager wheel 后运行 `fieldstation-console`。

打开 <http://127.0.0.1:18765/>。默认仅监听本机；按 Ctrl+C 停止。可用 `FIELDSTATION_CONSOLE_PORT` 指定端口。实际连接通过启动进程的环境变量注入，各服务可独立配置：

```powershell
$env:FIELDSTATION_IM_URL = 'http://127.0.0.1:18103'
$env:FIELDSTATION_IM_TOKEN = '<由可信宿主注入>'
$env:FIELDSTATION_BOARD_URL = 'http://127.0.0.1:18104'
$env:FIELDSTATION_BOARD_TOKEN = '<由可信宿主注入>'
$env:FIELDSTATION_QUEUE_URL = 'http://127.0.0.1:18105'
$env:FIELDSTATION_QUEUE_TOKEN = '<由可信宿主注入>'
$env:FIELDSTATION_HOST_URL = 'http://127.0.0.1:18106'
$env:FIELDSTATION_HOST_TOKEN = '<由可信宿主注入>'
```

地址仅为格式示例。令牌不会传给浏览器或写入工作台文件。实际授权由各服务检查，Host 目录仅返回当前主体允许查看的配置。工作台进程属于可信宿主，应由同一可信用户在本机使用；它没有提供多用户会话隔离。切勿将其反向代理或暴露到网络。

目前 IM 支持从已知 Issue 逐级展开子问题，查看当前结论和状态、Evidence 及其有向关系；Board 支持交流、请求和指令列表；Queue 支持待办列表和按领取状态筛选；Host 支持受限岗位目录。列表支持服务返回的续页，记录详情保留公开接口原始字段。实际服务未配置时不会将示例冒充真实数据。

Evidence 图使用环形布局呈现当前已加载材料及各材料已读取的直接关系；箭头与类型来自 IM。材料及关系均可能分页，界面会提示继续加载、读取失败或受限。节点颜色表示 IM 的质量状态，已作废优先显示为生命周期状态；外部节点未读取详情前标为未知。大图可以滚动，边可能交叉。
