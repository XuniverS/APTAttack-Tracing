$(document).ready(function() {
    const MAX_FILES = 1000;
    let files = { attack: [], tcp: [] };
    let currentPage = 1;
    const pageSize = 50;

    // 初始化上传区域（修改后）
    function initUploadBox(boxId, type) {
        const $box = $(`#${boxId}`);
        const $input = $(`#${type}FileInput`);
        const $list = $(`#${type}FileList`);

        $input.on('click', function(e) {
            e.stopPropagation();
        });

        // 点击容器触发文件选择
        $box.on('click', function(e) {
            // 只有当点击目标不是文件项且不是输入框本身时触发
            if (!$(e.target).closest('.file-item').length &&
                !$(e.target).is($input)) {
                $input[0].click();
            }
        });

        // 拖放处理（保持原逻辑不变）
        $box.on('dragover', function(e) {
            e.preventDefault();
            $box.addClass('highlight');
        }).on('dragleave drop', function(e) {
            e.preventDefault();
            $box.removeClass('highlight');
        }).on('drop', function(e) {
            const dt = e.originalEvent.dataTransfer;
            handleFiles(dt.files, type);
        });

        // 文件选择变化
        $input.on('change', function(e) {
            handleFiles(this.files, type);
        });

        // 删除文件（添加阻止冒泡）
        $list.on('click', '.remove-file', function(e) {
            e.stopPropagation();
            const index = $(this).closest('.file-item').index();
            files[type].splice(index, 1);
            updateFileList(type);
        });
    }

    function handleFiles(newFiles, type) {
        if (files[type].length + newFiles.length > MAX_FILES) {
            alert(`Maximum ${MAX_FILES} files allowed`);
            return;
        }

        const existingNames = files[type].map(f => f.name);
        const validFiles = Array.from(newFiles).filter(f =>
            !existingNames.includes(f.name)
        );

        files[type] = [...files[type], ...validFiles];
        updateFileList(type);
    }

    initUploadBox('attackUploadBox', 'attack');
    initUploadBox('tcpUploadBox', 'tcp');


    function updateFileList(type) {
        const $list = $(`#${type}FileList`);
        $list.empty();
        files[type].forEach((file, index) => {
            $list.append(`
                <div class="file-item">
                    <div class="file-info">
                        <div class="file-name">${file.name}</div>
                        <div class="file-size">${formatFileSize(file.size)}</div>
                    </div>
                    <div class="remove-file">×</div>
                </div>
            `);
        });
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }


    // 上传按钮点击事件
    $('#uploadBtn').on('click', async function() {
        const allFiles = [...files.attack, ...files.tcp];
        if (allFiles.length === 0) {
            alert('请先选择要上传的文件');
            return;
        }

        try {
            $(this).prop('disabled', true).text('分析中...');
            const formData = new FormData();

            // 修正字段名称为数组格式
            files.attack.forEach(file => {
                formData.append("attack", file);
            });
            files.tcp.forEach(file => {
                formData.append("tcp", file);
            });

            const response = await fetch('/api/v1/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.message || '上传失败');
            }

            const result = await response.json();
            handleUploadSuccess(result);

        } catch (error) {
            console.error('上传错误:', error);
            alert('上传失败: ' + error.message);
        } finally {
            $(this).prop('disabled', false).text('分析日志');
        }
    });

    function handleUploadSuccess(result) {
        files = { attack: [], tcp: [] };
        updateFileList('attack');
        updateFileList('tcp');
        alert(`Successfully processed ${result.processed} files`);
    }

    // 初始化定时刷新
    setInterval(loadLogs, refreshInterval);
    loadLogs();

    // 模态框关闭事件
    $('.close').click(() => $('#detailModal').hide());
});

async function loadLogs() {
    try {
        const res = await fetch(`/api/v1/refresh?page=${currentPage}&limit=${pageSize}`);
        const data = await res.json();

        if(data.status === 'success') {
            renderTable(data.data.events);
            updatePagination(data.data.total);
            updateHistory(data.data.events);
        }
    } catch (error) {
        console.error('刷新失败:', error);
    }
}

function renderTable(events) {
    const rows = events.map(event => `
        <tr data-id="${event.id}">
            <td>${new Date(event.starttime).toLocaleString()}</td>
            <td>${event.eventype}</td>
            <td>${event.sourceip}</td>
            <td>${event.destip}</td>
            <td class="severity-${event.severitylevel}">
                ${getSeverityLabel(event.severitylevel)}
            </td>
        </tr>
    `).join('');

    $('#logTable').html(`
        <table class="log-table">
            <thead>
                <tr>
                    <th>时间</th>
                    <th>类型</th>
                    <th>源IP</th>
                    <th>目标IP</th>
                    <th>严重等级</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `);

    $('.log-table tbody tr').click(function() {
        const id = $(this).data('id');
        showDetail(id);
    });
}

async function showDetail(id) {
    try {
        const res = await fetch('/api/v1/inquire', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: id })
        });

        const data = await res.json();
        if(data.status === 'success') {
            renderModal(data.data);
            $('#detailModal').show();
        }
    } catch (error) {
        console.error('获取详情失败:', error);
    }
}

function renderModal(event) {
    const protocolDisplay = event.protocol || 'TCP'; // 默认显示TCP
    const content = `
        <p><strong>事件名称:</strong> ${event.eventname}</p>
        <p><strong>开始时间:</strong> ${new Date(event.starttime).toLocaleString()}</p>
        <p><strong>结束时间:</strong> ${new Date(event.endtime).toLocaleString()}</p>
        <p><strong>协议:</strong> ${protocolDisplay}</p>
        <p><strong>源端口:</strong> ${event.src_port}</p>
        <p><strong>目标端口:</strong> ${event.dest_port}</p>
        <p><strong>状态码:</strong> ${event.status_code}</p>
        <p><strong>严重等级:</strong> ${getSeverityLabel(event.severitylevel)}</p>
        <hr>
        <p><strong>描述:</strong> ${event.description}</p>
        <div class="network-info">
            <h4>网络流量信息</h4>
            <p>发送字节: ${formatBytes(event.bytes_sent)}</p>
            <p>接收字节: ${formatBytes(event.bytes_received)}</p>
            <p>重传次数: ${event.retransmits}</p>
        </div>
    `;
    $('#modalContent').html(content);
}

function formatBytes(bytes) {
    if(bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i]);
}

function getSeverityLabel(level) {
    const labels = ['紧急', '严重', '高', '中', '低'];
    return labels[level - 1] || '未知';
}

function updateHistory(events) {
    const history = events.slice(0, 10).map(event => `
        <div class="history-item" data-id="${event.id}">
            <span class="time">${new Date(event.created_at).toLocaleTimeString()}</span>
            <span class="type">${event.event_type}</span>
        </div>
    `).join('');

    $('#historyList').html(history);
    $('.history-item').click(function() {
        const id = $(this).data('id');
        showDetail(id);
    });
}

function updatePagination(total) {
    const totalPages = Math.ceil(total / pageSize);
    const buttons = Array.from({length: totalPages}, (_, i) => `
        <button class="page-btn ${i+1 === currentPage ? 'active' : ''}" 
                onclick="changePage(${i+1})">
            ${i+1}
        </button>
    `).join('');

    $('#pagination').html(buttons);
}

window.changePage = function(page) {
    currentPage = page;
    loadLogs();
};