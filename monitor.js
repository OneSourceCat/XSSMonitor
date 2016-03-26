(function(){

var GlobalObj = {} ;
var Utils = {} ;

/**
 * 工具类 获取url中的hostName
 * @param  {[String]} url 
 */
Utils.getHostName = function(url){
    console.log(url) ;
    var reg = /^https?:\/\/(.*?)\/?.+?/ig ;
    var domain = url.match(reg)[0] ;
    return domain ;
}

GlobalObj.reportURL = "http://127.0.0.1:8000/report" ;


//保留接口
GlobalObj._alert = window.alert ;
GlobalObj._prompt = window.prompt ;
GlobalObj._createElement = document.createElement ;
GlobalObj._Image = Image ;

GlobalObj.Attack_Stack = [] ;
GlobalObj.isChrome = function(){
    if(navigator.appName == "Microsoft Internet Explorer"){
        return false ;
    }else{
        return true ;
    }
} ;

GlobalObj.isTrustDomain = function(url){
    if(!monitorConfig.white_list){
        console.log("配置错误") ;
        return ;
    }else{
        var domain = Utils.getHostName(url) ;
        if(domain in monitorConfig.white_list){
            return true ;
        }else{
            return false ;
        }
    }
} ;

GlobalObj.defConstProp = function(obj, property, val){
    Object.defineProperty(obj, property, {
        value: val,
        configurable: 0,
        writable: 0,
        enumerable: 1
    });
} ;

GlobalObj.Protect_hook = function(){
    /**
     * 保护一些判别函数，防止攻击者进行hook
     */
    GlobalObj.defConstProp(window, "alert", alert) ;
    GlobalObj.defConstProp(window, "confirm", confirm) ; 
    GlobalObj.defConstProp(window, "prompt", prompt) ;
    GlobalObj.defConstProp(window, "Image", Image) ;
    GlobalObj.defConstProp(document, "createElement", document.createElement) ;
    GlobalObj.defConstProp(RegExp.prototype, "test", RegExp.prototype.test) ;
    GlobalObj.defConstProp(HTMLElement.prototype, "appendChild", HTMLElement.prototype.appendChild) ;
    GlobalObj.defConstProp(window.Element.prototype, "setAttribute", window.Element.prototype.setAttribute) ;
    GlobalObj.defConstProp(window.Element.prototype, "getAttribute", window.Element.prototype.getAttribute) ;
    GlobalObj.defConstProp(String.prototype, "toLowerCase", String.prototype.toLowerCase) ;
    GlobalObj.defConstProp(String.prototype, "indexOf", String.prototype.indexOf) ;
    GlobalObj.defConstProp(String.prototype, "replace", String.prototype.replace) ;
    GlobalObj.defConstProp(window, "call", window.call) ;
    GlobalObj.defConstProp(window, "apply", window.apply) ;
} ;

GlobalObj.Report = function(domain, info){
    /**
     * 报警模块:使用ajax跨域请求，收不到response
     * 设置header为：Access-Control-Allow-Origin:*
     */
    info = info.join("|") ;
    var time = Date.now() ;
    var token = monitorConfig.token ;
    var report_url = GlobalObj.reportURL + "?" ;
    report_url += "d=" + domain +"&";
    report_url += "p=" + monitorConfig.project_name +"&";
    report_url += "f=" + encodeURIComponent(info) + "&";
    report_url += "t=" + time ;
    console.log(report_url) ;
    //利用ajax加载跨域发送请求
    console.log("domain:" + domain) ;
    console.log("info:" + info) ;
    try{
        var xhr = new XMLHttpRequest() ; 
        console.log("xxx") ;
        xhr.open("GET", report_url, true) ; 
        xhr.send() ;
    }catch(e){
        console.log(e) ;
    }

} ;

GlobalObj.Hook_CreateElement = function(){
    /**
     * 对元素的创建进行hook
     */
    document.createElement = function(ele){
        //填充攻击路径
        var type = ["C_SCRIPT", "C_IFRAME", "C_IMAGE", "SCRIPT.SRC$"] ; 
        GlobalObj.Attack_Stack = [] ;
        console.log(ele) ;
        var ele_name = ele.toLowerCase() ;
        if(ele_name == "script"){
            GlobalObj.Attack_Stack.push(type[0]) ;
        }else if(ele_name in ["iframe", "frame"]){
            GlobalObj.Attack_Stack.push(type[1]) ;
        }else if(ele_name == "image"){
            GlobalObj.Attack_Stack.push(type[2]) ;
        }
        new_ele = GlobalObj._createElement.call(document, ele) ;
        Object.defineProperty(new_ele, "src", {
            get: function(){
                return new_ele.getAttribute('src') ;
            },
            set: function(val){
                if(GlobalObj.isTrustDomain(val)){
                    new_ele.setAttribute("src", val) ;
                }else{
                    //检测到创建链接到第三方js的script元素
                    if(ele_name == "script"){
                        GlobalObj.Attack_Stack.push(type[3] + val) ;
                        console.log(GlobalObj.Attack_Stack) ;
                        var domain = Utils.getHostName(val) ;
                        GlobalObj.Report(domain, GlobalObj.Attack_Stack) ;
                        confirm("发现第三方不可信javascript嵌入:" + val + "\n" + "是否进行拦截？")?this.setAttribute("src", ""):this.setAttribute("src", val) ;
                    }
                }
            }
        });
        return new_ele ;
    }
    console.log("HOOK CreateElement") ;
} ;


GlobalObj.Hook_Image = function(){
    /**
     * 对Image图像创建进行hook
     */
    var t = ["C_IMAGE", "IMG.SRC$"] ;
    GlobalObj.Attack_Stack = [] ;
    Image = function(){
        var i = new GlobalObj._Image ;
        GlobalObj.Attack_Stack.push(t[0]) ;
        Object.defineProperty(i, "src", {
            get: function(){
                return this.getAttribute('src') ;
            },
            set: function(src){
                if(GlobalObj.isTrustDomain(src)){
                    this.setAttribute("src", src) ;
                }else{
                    //检测到通过(new Image()).src的方式加载第三方资源
                    GlobalObj.Attack_Stack.push(t[1] + src) ;
                    console.log(GlobalObj.Attack_Stack) ;
                    var domain = Utils.getHostName(src) ;
                    GlobalObj.Report(domain, GlobalObj.Attack_Stack) ;
                    confirm("发现第三方不可信Image嵌入，可能有丢失数据的风险,是否进行拦截？\n"+ src)? this.setAttribute("src", "") : this.setAttribute("src", src);
                }
            }
        });
        return i ;
    }

} ;


GlobalObj.Hook_DOM = function(){
    /**
     * 监控DOM节点的变化
     */
    var info = ["C_Element", "ELE.NAME$", "ELE.SRC$"] ;
    var thirdEles = ["a", "frame", "iframe", "link", "object", "embed", 
                    "video", "img", "source", "audio"] ;

    var mo = new MutationObserver(function(records){
        records.map(function(record){
            var nodes = record.addedNodes ;
            for(var i=0; i<nodes.length; i++){
                var ele = nodes[i] ;
                console.log("createElement:" + ele.tagName) ;
                if(ele.tagName && (ele.tagName.toLowerCase() in thirdEles)){
                    if(ele.src || ele.href || ele.data){
                        var url = ele.src || ele.href || ele.data ;
                        if(!GlobalObj.isTrustDomain(url)){
                            var domain = Utils.getHostName(url) ;
                            GlobalObj.Attack_Stack = [] ;
                            GlobalObj.Attack_Stack.push(info[0]) ;
                            GlobalObj.Attack_Stack.push(info[1] + ele.tagName) ;
                            GlobalObj.Attack_Stack.push(info[2] + domain) ;
                            GlobalObj.Report(domain, GlobalObj.Attack_Stack) ;
                            if(confirm("监控到危险元素" + ele.tagName + "创建\n" + "是否进行拦截？" + url)){
                                ele.parentElement.removeChild(ele) ;
                            }
                        }
                    }
                }

                //处理script标签的创建
                if(ele.src && ele.tagName.toLowerCase() == "script"){
                    if(!GlobalObj.isTrustDomain(ele.src)){
                        GlobalObj.Attack_Stack = [] ;
                        var domain = Utils.getHostName(ele.src) ;
                        GlobalObj.Attack_Stack.push("C_SCRIPT") ;
                        GlobalObj.Attack_Stack.push(domain) ;
                        GlobalObj.Report(domain, GlobalObj.Attack_Stack) ;
                        if(confirm("发现第三方不可信Image嵌入，可能有丢失数据的风险,是否进行拦截？\n"+ ele.src)){
                            ele.parentElement.removeChild(ele) ;
                        }
                    }   
                }
                
            }
        }) ;
    }) ;

    mo.observe(document, {
        subtree: true,
        childList: true
    }) ;

};


//执行主流程
GlobalObj.Hook_CreateElement() ;
GlobalObj.Hook_Image() ;
GlobalObj.Hook_DOM() ;
GlobalObj.Protect_hook() ;

})() ;


