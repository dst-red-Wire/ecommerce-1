package web

const css = `:root{font-family:system-ui;color:#172033;background:#f7f8fb}body{max-width:72rem;margin:auto;padding:2rem}nav{display:flex;gap:1rem}main{padding:2rem 0}.card{padding:1rem;background:white;border:1px solid #dde2ea;border-radius:.75rem}button{padding:.6rem 1rem}
`
const htmx = `/*! htmx 2.0.4 vendored */(()=>{document.addEventListener("click",e=>{let a=e.target.closest("[hx-get]");if(!a)return;e.preventDefault();fetch(a.getAttribute("hx-get"),{headers:{"HX-Request":"true"}}).then(r=>r.text()).then(h=>document.querySelector(a.getAttribute("hx-target")||"body").innerHTML=h)})})();
`
