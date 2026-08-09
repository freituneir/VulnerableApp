function addingEventListenerToUploadImage() {
  document.getElementById("upload").addEventListener("click", function () {
    var form = document.getElementById("file");
    var file = form.files[0];
    var formData = new FormData();
    formData.append("file", file);
    let url = getUrlForVulnerabilityLevel();
    doPostAjaxCall(uploadImage, url, true, formData);
  });
}
addingEventListenerToUploadImage();

function uploadImage(data) {
  // The echoed location is derived from the uploaded file, so it is rendered as text rather than
  // parsed as HTML: a file name is never markup.
  document.getElementById("uploaded_file_info").textContent = data.isValid
    ? "File uploaded at location:" + data.content
    : data.content;
}
