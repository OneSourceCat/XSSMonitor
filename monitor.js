(function(){

var GlobalObj = {} ;
var Utils = {} ;

/**
 * 工具类 获取url中的hostName
 * @param  {[String]} url 
 */
Utils.getHostName = function(url){
    console.log(url) ;
    var reg = /https?:\/\/(.*?)\/?/ig ;
    var domain = url.match(reg)[0] ;
    return domain ;
}

GlobalObj.reportURL = "http://127.0.0.1:8000/report" ;
GlobalObj._type = [
    "C_SCRIPT", "C_IFRAME", "C_IMAGE", 
    "SCRIPT.SRC:", "C_INPUT_TYPE_PWD", 
    "C_INPUT", "FISH", "FRAME.SRC:", 
    "URL_2L", "C_SCRIPT_3"
] ;


//保留接口
GlobalObj._alert = window.alert ;
GlobalObj._prompt = window.prompt ;
GlobalObj._createElement = document.createElement ;

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
    XMLHttpRequest && (GlobalObj.defConstProp(window, "XMLHttpRequest", XMLHttpRequest) ,
    GlobalObj.defConstProp(XMLHttpRequest.prototype, "send", XMLHttpRequest.prototype.send)) ;
    GlobalObj.defConstProp(window.Element.prototype, "setAttribute", window.Element.prototype.setAttribute) ;
    GlobalObj.defConstProp(window.Element.prototype, "getAttribute", window.Element.prototype.getAttribute) ;
    GlobalObj.defConstProp(String.prototype, "toLowerCase", String.prototype.toLowerCase) ;
    GlobalObj.defConstProp(String.prototype, "indexOf", String.prototype.indexOf) ;
    GlobalObj.defConstProp(String.prototype, "replace", String.prototype.replace) ;
} ;

GlobalObj.Report = function(domain, info){
    /**
     * 报警模块:使用ajax跨域请求，收不到response
     */
    info = info.join("|") ;
    var time = Date.now() ;
    var token = monitorConfig.token ;
    var report_url = GlobalObj.reportURL + "?" ;
    report_url += "d=" + domain +"&";
    report_url += "f=" + encodeURIComponent(info) + "&";
    report_url += "t=" + time ;

    //利用ajax加载跨域发送请求
    if(GlobalObj.isWebkit){
       var xhr = new XMLHttpRequest() ; 
    }else{
       console.log("不支持的浏览器类型") ;
    }
    try{
       xhr.open("GET", report_url, true) ; 
    }catch(e){
        console.log("Ajax forward!") ;
    }
} ;

GlobalObj.Hook_CreateElement = function(){
    /**
     * 对元素的创建进行hook
     */
    document.createElement = function(ele){
        //填充攻击路径
        var type = GlobalObj._type ;
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
                        GlobalObj.Attack_Stack.push(type[9]) ;
                        GlobalObj.Attack_Stack.push(val) ;
                        console.log(GlobalObj.Attack_Stack) ;
                        var domain = Utils.getHostName(val) ;
                        GlobalObj.Report(domain, GlobalObj.Attack_Stack) ;
                        alert("发现第三方不可信javascript嵌入:" + val)
                    }
                }
            }
        });
        return new_ele ;
    }
    console.log("HOOK CreateElement") ;
} ;


//执行主流程
GlobalObj.Hook_CreateElement() ;

GlobalObj.Protect_hook() ;

})() ;


