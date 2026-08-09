function addingEventListenerToPingButton() {
  document.getElementById("pingBtn").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      pingUtilityCallback,
      url + "?ipaddress=" + document.getElementById("ipaddress").value,
      true
    );
  });
}
addingEventListenerToPingButton();

function pingUtilityCallback(data) {
  // The body carries whatever the ping utility wrote, which is derived from the submitted host.
  // Parsing it as HTML would let that value become markup in the app's own origin, so it is
  // written as a text node instead.
  document.getElementById("pingUtilityResponse").textContent = data.content;
}
