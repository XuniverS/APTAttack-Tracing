$(document).ready(function() {
    const MAX_FILES = 10;
    let files = {
        attack: [],
        tcp: []
    };

    function initUploadBox(boxId, type) {
        const $box = $(`#${boxId}`);
        const $input = $(`#${type}FileInput`);
        const $list = $(`#${type}FileList`);

        $box.on('click', function(e) {
            if (!$(e.target).closest('.file-item').length) {
                $input.click();
            }
        });

        $box.on('dragover', function(e) {
            e.preventDefault();
            $box.addClass('highlight');
        }).on('dragleave', function(e) {
            e.preventDefault();
            $box.removeClass('highlight');
        }).on('drop', function(e) {
            e.preventDefault();
            $box.removeClass('highlight');
            handleFiles(e.originalEvent.dataTransfer.files, type);
        });

        $input.on('change', function(e) {
            handleFiles(this.files, type);
        });

        $list.on('click', '.remove-file', function() {
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

    initUploadBox('attackUploadBox', 'attack');
    initUploadBox('tcpUploadBox', 'tcp');

    $('#uploadBtn').on('click', async function() {
        const allFiles = [...files.attack, ...files.tcp];
        if (allFiles.length === 0) {
            alert('Please select files to upload');
            return;
        }

        try {
            $(this).prop('disabled', true).text('Analyzing...');

            const formData = new FormData();
            files.attack.forEach(file => {
                formData.append('attack', file);
            });

            files.tcp.forEach(file => {
                formData.append('tcp', file);
            });

            const response = await fetch('/api/v1/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error('Upload failed');

            const result = await response.json();
            handleUploadSuccess(result);

        } catch (error) {
            console.error('Upload error:', error);
            alert('Error uploading files: ' + error.message);
        } finally {
            $(this).prop('disabled', false).text('Analyze Logs');
        }
    });

    function handleUploadSuccess(result) {
        files = { attack: [], tcp: [] };
        updateFileList('attack');
        updateFileList('tcp');
        alert(`Successfully processed ${result.processed} files`);
    }
});