chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  if (req.action === "update_badge" && sender.tab) {
    const n = req.count || 0;
    const color = n >= 10 ? "#e74c3c" : n >= 4 ? "#e67e22" : n >= 1 ? "#f1c40f" : "#2ecc71";
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color });
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: n > 0 ? String(n) : "" });
  }

  // Main world probe — bypasses CSP by executing via chrome.scripting API
  if (req.action === "probe_main_world" && sender.tab) {
    chrome.scripting.executeScript({
      target: { tabId: sender.tab.id },
      world: "MAIN",
      func: () => {
        var r = {};
        try{var jq=window.jQuery||window.$;if(jq&&jq.fn&&jq.fn.jquery)r.jquery={v:jq.fn.jquery,m:"jQuery.fn.jquery"}}catch(e){}
        try{if(window.jQuery&&window.jQuery.ui&&window.jQuery.ui.version)r["jquery-ui"]={v:window.jQuery.ui.version,m:"jQuery.ui.version"}}catch(e){}
        try{var u=window._;if(u&&u.VERSION)r.lodash={v:u.VERSION,m:"_.VERSION"}}catch(e){}
        try{if(window.angular&&window.angular.version)r.angularjs={v:window.angular.version.full,m:"angular.version.full"}}catch(e){}
        try{var ngEl=document.querySelector("[ng-version]");if(ngEl)r.angular={v:ngEl.getAttribute("ng-version"),m:"ng-version attr"}}catch(e){}
        try{if(window.Vue&&window.Vue.version)r.vue={v:window.Vue.version,m:"Vue.version"}}catch(e){}
        try{if(window.__VUE__)r.vue=r.vue||{v:"detected",m:"__VUE__"}}catch(e){}
        try{if(window.React&&window.React.version)r.react={v:window.React.version,m:"React.version"}}catch(e){}
        try{if(window.ReactDOM&&window.ReactDOM.version)r["react-dom"]={v:window.ReactDOM.version,m:"ReactDOM.version"}}catch(e){}
        try{var hook=window.__REACT_DEVTOOLS_GLOBAL_HOOK__;if(hook&&hook.renderers&&hook.renderers.size>0){var rend=hook.renderers.values().next().value;if(rend&&rend.version){if(!r.react)r.react={v:rend.version,m:"DevTools hook"};if(!r["react-dom"])r["react-dom"]={v:rend.version,m:"DevTools hook"}}}}catch(e){}
        try{if(window.moment&&window.moment.version)r.moment={v:window.moment.version,m:"moment.version"}}catch(e){}
        try{if(window.axios&&window.axios.VERSION)r.axios={v:window.axios.VERSION,m:"axios.VERSION"}}catch(e){}
        try{if(window.bootstrap&&window.bootstrap.Tooltip&&window.bootstrap.Tooltip.VERSION)r.bootstrap={v:window.bootstrap.Tooltip.VERSION,m:"bootstrap.Tooltip.VERSION"}}catch(e){}
        try{if(window.DOMPurify&&window.DOMPurify.version)r.dompurify={v:window.DOMPurify.version,m:"DOMPurify.version"}}catch(e){}
        try{if(window.Handlebars&&window.Handlebars.VERSION)r.handlebars={v:window.Handlebars.VERSION,m:"Handlebars.VERSION"}}catch(e){}
        try{if(window.hljs&&window.hljs.versionString)r["highlight.js"]={v:window.hljs.versionString,m:"hljs.versionString"}}catch(e){}
        try{if(window.ko&&window.ko.version)r.knockout={v:window.ko.version,m:"ko.version"}}catch(e){}
        try{if(window.Backbone&&window.Backbone.VERSION)r.backbone={v:window.Backbone.VERSION,m:"Backbone.VERSION"}}catch(e){}
        try{if(window.Ember&&window.Ember.VERSION)r.ember={v:window.Ember.VERSION,m:"Ember.VERSION"}}catch(e){}
        try{if(window.next&&window.next.version)r.next={v:window.next.version,m:"next.version"}}catch(e){}
        try{if(window.__NEXT_DATA__){r.next=r.next||{v:"detected",m:"__NEXT_DATA__"};r.next.buildId=window.__NEXT_DATA__.buildId;r.next.fields=Object.keys(window.__NEXT_DATA__)}}catch(e){}
        try{if(window.marked&&window.marked.version)r.marked={v:window.marked.version,m:"marked.version"}}catch(e){}
        try{if(window.d3&&window.d3.version)r.d3={v:window.d3.version,m:"d3.version"}}catch(e){}
        try{if(window.Chart&&window.Chart.version)r["chart.js"]={v:window.Chart.version,m:"Chart.version"}}catch(e){}
        try{if(window.videojs&&window.videojs.VERSION)r["video.js"]={v:window.videojs.VERSION,m:"videojs.VERSION"}}catch(e){}
        try{if(window.L&&window.L.version)r.leaflet={v:window.L.version,m:"L.version"}}catch(e){}
        try{if(window.Plyr)r.plyr={v:"detected",m:"Plyr global"}}catch(e){}
        try{if(window.Swal&&window.Swal.version)r.sweetalert2={v:window.Swal.version,m:"Swal.version"}}catch(e){}
        try{if(window.Prism&&window.Prism.manual!==undefined)r.prismjs={v:"detected",m:"Prism global"}}catch(e){}
        try{if(window.tinymce&&window.tinymce.majorVersion)r.tinymce={v:window.tinymce.majorVersion+"."+window.tinymce.minorVersion,m:"tinymce global"}}catch(e){}
        try{if(window.CKEDITOR&&window.CKEDITOR.version)r.ckeditor={v:window.CKEDITOR.version,m:"CKEDITOR.version"}}catch(e){}
        try{if(window.Swiper)r.swiper={v:"detected",m:"Swiper global"}}catch(e){}
        try{if(window.flatpickr&&window.flatpickr.defaultConfig)r.flatpickr={v:"detected",m:"flatpickr global"}}catch(e){}
        try{if(window.DataTable)r.datatables={v:"detected",m:"DataTable global"}}catch(e){}
        try{if(window.Alpine)r.alpinejs={v:window.Alpine.version||"detected",m:"Alpine global"}}catch(e){}
        try{if(window.htmx&&window.htmx.version)r.htmx={v:window.htmx.version,m:"htmx.version"}}catch(e){}
        try{if(window.THREE&&window.THREE.REVISION)r.three={v:"r"+window.THREE.REVISION,m:"THREE.REVISION"}}catch(e){}
        try{if(window.MathJax&&window.MathJax.version)r.mathjax={v:window.MathJax.version,m:"MathJax.version"}}catch(e){}
        try{if(window.i18next&&window.i18next.version)r.i18next={v:window.i18next.version,m:"i18next.version"}}catch(e){}
        try{if(window.io&&window.io.protocol)r["socket.io"]={v:"detected",m:"io.protocol"}}catch(e){}

        // Webpack chunk analysis
        try{
          var wpKeys=Object.keys(window).filter(function(k){return k.indexOf("webpackChunk")===0});
          if(wpKeys.length>0){
            r.__webpack={detected:true,keys:wpKeys};
            for(var wi=0;wi<wpKeys.length;wi++){
              var arr=window[wpKeys[wi]];
              if(!Array.isArray(arr))continue;
              for(var ci=0;ci<Math.min(arr.length,10);ci++){
                var chunk=arr[ci];
                if(!Array.isArray(chunk)||chunk.length<2)continue;
                var mods=chunk[1];
                if(!mods||typeof mods!=="object")continue;
                var modKeys=Object.keys(mods).slice(0,50);
                for(var mi=0;mi<modKeys.length;mi++){
                  try{
                    var src=mods[modKeys[mi]].toString().substring(0,500);
                    var vm=src.match(/version\s*[=:]\s*["'](\d+\.\d+\.\d+[^"']*)["']/);
                    if(vm)r.__wpVersions=(r.__wpVersions||[]).concat({moduleId:modKeys[mi],version:vm[1],ctx:src.substring(Math.max(0,vm.index-30),vm.index+60)});
                  }catch(e2){}
                }
              }
            }
          }
        }catch(e){}

        // React DOM property detection
        try{
          var root=document.getElementById("__next")||document.getElementById("root")||document.getElementById("app")||document.querySelector("[data-reactroot]");
          if(root){
            var keys=Object.keys(root);
            var reactDOM={};
            for(var ki=0;ki<keys.length;ki++){
              if(keys[ki].indexOf("__reactContainer$")===0)reactDOM.container18=true;
              if(keys[ki].indexOf("__reactFiber$")===0)reactDOM.fiber17=true;
              if(keys[ki].indexOf("__reactInternalInstance$")===0)reactDOM.internal16=true;
            }
            if(Object.keys(reactDOM).length>0)r.__reactDOM=reactDOM;
          }
        }catch(e){}

        // React feature detection
        try{
          if(window.React){
            var feats={};
            if(typeof window.React.use==="function")feats.use=true;
            if(typeof window.React.useId==="function")feats.useId=true;
            if(typeof window.React.startTransition==="function")feats.startTransition=true;
            if(typeof window.React.lazy==="function")feats.lazy=true;
            if(Object.keys(feats).length>0)r.__reactFeatures=feats;
          }
        }catch(e){}

        return r;
      }
    }).then(results => {
      const data = (results && results[0] && results[0].result) ? results[0].result : {};
      sendResponse(data);
    }).catch(() => {
      sendResponse({});
    });
    return true; // async
  }
});
