let currentPath = "";

document.addEventListener("DOMContentLoaded", () => fetchFiles(currentPath));

async function fetchFiles(pathToFetch) {
    const fileListDiv = document.getElementById('fileList');
    fileListDiv.innerHTML = "<p>Loading files...</p>";

    try {
        const response = await fetch(`/api/files?path=${encodeURIComponent(pathToFetch)}`);
        if (!response.ok) {
            throw new Error("Failed to load directory");
        }

        const files = await response.json();
        currentPath = pathToFetch;
        renderFileList(files);

    } catch (error) {
       fileListDiv.innerHTML = `<p style="color:red;">Error: ${error.message}</p>`;
    }
}

function renderFileList(files) {
    const fileListDiv = document.getElementById('fileList');
    fileListDiv.innerHTML = "";

    if (currentPath !== "") {
        const backButton = document.createElement('div');
        backButton.className = "file-item";
        backButton.innerHTML = `<strong><a href="#" onclick="goBack(); return false;">⬅️ Up a Directory</a></strong>`;
        fileListDiv.appendChild(backButton);
    }

    if (!files || files.length === 0) {
        fileListDiv.innerHTML = "<p>Folder is empty.</p>";
        return;
    }

    files.forEach(file => {
        const div = document.createElement('div');
        div.className = "file-item";

        const itemLink= document.createElement('a');
        itemLink.href = "#";

        if (file.isDir) {
            itemLink.innerText = `📁 ${file.name}`;
            itemLink.onclick = (e) => {
                e.preventDefault();
                const newPath = currentPath ? `${currentPath}/${file.name}` : file.name;
                fetchFiles(newPath);
            };
        } else {
            itemLink.innerText = `📄 ${file.name}`;
            itemLink.onclick = (e) => {
                e.preventDefault();
                openFileViewer(file.name);
            };
        }

        const sizeSpan = document.createElement('span');
        sizeSpan.className = "file-size";
        sizeSpan.innerText = file.isDir ? "" : `${(file.size / 1024).toFixed(1)} KB`;

        div.appendChild(itemLink);
        div.appendChild(sizeSpan);
        fileListDiv.appendChild(div);
    });
}

function goBack() {
    const parts = currentPath.split('/');
    parts.pop();
    const parentPath = parts.join('/');
    fetchFiles(parentPath);
}

function openFileViewer(fileName) {
    const filePath = currentPath ? `${currentPath}/${fileName}` : fileName;
    const fileUrl = `/files/${encodeURIComponent(filePath)}`;

    document.getElementById('modalTitle').innerText = fileName;
    document.getElementById('fileIframe').src = fileUrl;
    document.getElementById('fileModal').style.display = "flex";
}

function closeModal() {
    document.getElementById('fileModal').style.display = "none";
    document.getElementById('fileIframe').src = "";
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const statusText = document.getElementById('status');
    const uploadBtn = document.querySelector('button[onclick="uploadFile()"]');

    if (fileInput.files.length === 0) {
       statusText.innerText = "⚠️ Please select a file first.";
        statusText.style.color = "orange";
        return;    
    }

    const files = Array.from(fileInput.files);
    let successCount = 0;
    let failCount = 0;
    console.log(`File length = ${files.length}`)

    uploadBtn.disabled = true;
    uploadBtn.style.opacity = "0.5";

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        console.log(`Uploading file ${i + 1}`)

        statusText.innerText = `⏳ Uploading ${i + 1} of ${files.length}: ${file.name}...`;
        statusText.style.color = "blue";

        const formData = new FormData();
        formData.append("myFile", file);

        try {
            const uploadUrl = currentPath
                ? `/api/upload?path=${encodeURIComponent(currentPath)}`
                : '/api/upload';

            const response = await fetch(uploadUrl, {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                successCount++
            } else {
                failCount++
                console.error(`Failed to upload ${file.name}:`, response.statusText);
            }
        } catch (error) {
            failCount++
            console.error(`Network error on ${file.name}:`, error);
        }
    }

    if (failCount === 0) {
        statusText.innerText = `✅ Successfully uploaded ${successCount} file(s)!`;
        statusText.style.color = "green";
    } else {
        statusText.innerText = `⚠️ Uploaded ${successCount}, Failed ${failCount}. Check browser console.`;
        statusText.style.color = "orange";
    }

    fileInput.value = "";
    uploadBtn.disabled = false;
    uploadBtn.style.opacity = "1";
    fetchFiles(currentPath);
}
