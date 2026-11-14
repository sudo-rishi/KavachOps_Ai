export async function saveBlobWithPicker(blob, filename, mime = "application/octet-stream") {
  if (!("showSaveFilePicker" in window)) {
    return false;
  }

  const handle = await window.showSaveFilePicker({
    suggestedName: filename,
    types: [
      {
        description: "Downloaded file",
        accept: {
          [mime]: [filename.includes(".") ? `.${filename.split(".").pop()}` : ".bin"],
        },
      },
    ],
  });

  const writable = await handle.createWritable();
  await writable.write(blob);
  await writable.close();
  return true;
}

export function triggerBrowserDownload(blob, fileName) {
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();

  setTimeout(() => {
    link.remove();
    URL.revokeObjectURL(objectUrl);
  }, 1000);
}
