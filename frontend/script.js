// 全局常量定义
const MAX_FILES = 1000;
const pageSize = 50;
const refreshInterval = 5000; // 5秒刷新间隔

// 全局变量声明
let currentPage = 1;
let files = { attack: [], tcp: [] };

$(document).ready(function() {
    // 初始化上传区域
    function initUploadBox(boxId, type) {
        const $box = $(`#${boxId}`);
        const $input = $(`#${type}FileInput`);
        const $list = $(`#${type}FileList`);

        // 阻止输入框点击冒泡
        $input.on('click', function(e) {
            e.stopPropagation();
        });

        // 容器点击触发文件选择
        $box.on('click', function(e) {
            if (!$(e.target).closest('.file-item').length &&
                !$(e.target).is($input)) {
                console.log('Triggering file input click');
                $input[0].click();
            }
        });

        // 拖放处理
        $box.on('dragover', function(e) {
            e.preventDefault();
            $box.addClass('highlight');
        }).on('dragleave drop', function(e) {
            e.preventDefault();
            $box.removeClass('highlight');
        }).on('drop', function(e) {
            const dt = e.originalEvent.dataTransfer;
            console.log('Dropped files:', dt.files);
            handleFiles(dt.files, type);
        });

        // 文件选择变化
        $input.on('change', function(e) {
            console.log('File input changed:', this.files);
            handleFiles(this.files, type);
        });

        // 删除文件
        $list.on('click', '.remove-file', function(e) {
            e.stopPropagation();
            const index = $(this).closest('.file-item').index();
            files[type].splice(index, 1);
            updateFileList(type);
        });
    }

    // 处理文件选择
    function handleFiles(newFiles, type) {
        if (files[type].length + newFiles.length > MAX_FILES) {
            alert(`最多允许上传 ${MAX_FILES} 个文件`);
            return;
        }

        const existingNames = files[type].map(f => f.name);
        const validFiles = Array.from(newFiles).filter(f =>
            !existingNames.includes(f.name)
        );

        files[type] = [...files[type], ...validFiles];
        updateFileList(type);
    }

    // 更新文件列表显示
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

    // 初始化上传区域
    initUploadBox('attackUploadBox', 'attack');
    initUploadBox('tcpUploadBox', 'tcp');

    // 上传按钮点击处理
    $('#uploadBtn').on('click', async function() {
        const allFiles = [...files.attack, ...files.tcp];
        if (allFiles.length === 0) {
            alert('请先选择要上传的文件');
            return;
        }

        try {
            $(this).prop('disabled', true).text('分析中...');
            const formData = new FormData();

            files.attack.forEach(file => formData.append("attack", file));
            files.tcp.forEach(file => formData.append("tcp", file));

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

    // 上传成功处理
    function handleUploadSuccess(result) {
        files = { attack: [], tcp: [] };
        updateFileList('attack');
        updateFileList('tcp');
        alert(`成功处理 ${result.processed} 个文件`);
    }

    // 日志加载功能
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

    // 渲染表格
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

    // 显示详情模态框
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

    // 更新分页
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

    // 工具函数
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function getSeverityLabel(level) {
        const labels = ['紧急', '严重', '高', '中', '低'];
        return labels[level - 1] || '未知';
    }

    // 初始化定时任务
    setInterval(loadLogs, refreshInterval);
    loadLogs();

    // 暴露分页函数到全局
    window.changePage = function(page) {
        currentPage = page;
        loadLogs();
    };

    // 模态框关闭
    $('.close').click(() => $('#detailModal').hide());
});