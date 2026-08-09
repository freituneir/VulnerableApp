function addingEventListenerToLoadImageButton() {
  document.getElementById("loadButton").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      appendResponseCallback,
      url + "?fileName=" + document.getElementById("fileName").value,
      true
    );
  });
}
addingEventListenerToLoadImageButton();

function appendResponseCallback(data) {
  // The table is assembled from DOM nodes with each cell set as text. It used to be built by
  // concatenating the contents of the requested file into an HTML string, so the file decided
  // the markup of this page.
  const container = document.getElementById("Information");
  container.replaceChildren();

  if (!data.isValid) {
    container.textContent = "Unable to Load Users";
    return;
  }

  let content;
  try {
    content = JSON.parse(data.content);
  } catch (e) {
    container.textContent = "Unable to Load Users";
    return;
  }

  const table = document.createElement("table");
  table.id = "InfoTable";

  if (content.length > 0) {
    const headerRow = document.createElement("tr");
    for (let key in content[0]) {
      const header = document.createElement("th");
      header.id = "InfoColumn";
      header.textContent = key;
      headerRow.appendChild(header);
    }
    table.appendChild(headerRow);
  }

  for (let index in content) {
    const row = document.createElement("tr");
    row.id = "Info";
    for (let key in content[index]) {
      const cell = document.createElement("td");
      cell.id = "InfoColumn";
      cell.textContent = content[index][key];
      row.appendChild(cell);
    }
    table.appendChild(row);
  }

  container.appendChild(table);
}
