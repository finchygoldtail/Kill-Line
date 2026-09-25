"use strict";
const $ = (id) => document.getElementById(id);
function show(which) {
  for (const id of ["idle", "busy", "failed"]) $(id).hidden = id !== which;
}
async function start() {
  show("busy");
  try {
    const r = await window.__TAURI__.core.invoke("start_backend");
    $("busy-text").textContent = "Opening the dashboard…";
    window.location.replace(r.url);
  } catch (e) {
    $("error").textContent = String(e);
    show("failed");
    $("retry").focus();
  }
}
$("go").addEventListener("click", start);
$("retry").addEventListener("click", start);
// Start straight away: the permission prompt is the only step.
start();
