$(document).ready(function() {

    $("#create_btn_submit").click(function(){
        //创建项目
        var url = "http://127.0.0.1:8000/create"
        var project_name = $("#project_name").val() ;
        var white_list = $("#white_list").val() ;
        $.post(url, {'project_name': project_name, "white_list": white_list}, function(data, textStatus){
            data = $.parseJSON(data) ;
            if(data.code == 1){
                alert("创建成功！") ;
                $("#project_name").val("")
                $("#white_list").val("")
            }else{
                alert("创建失败!失败原因：" + data.error) ;
            }
        })
    }) ;

});

var delete_project = function(id){
    var url = "http://127.0.0.1:8000/del_project" ;
    $.post(url, {"pid": id}, function(data, status){
        data = $.parseJSON(data) ;
        if(data.code == 1){
            location.href = "http://127.0.0.1:8000/showproject" ;
        }else{
            alert("创建失败!失败原因：" + data.error) ;
        }
    }) ;
}

var delete_alert = function(id){
    var url = "http://127.0.0.1:8000/del_alert" ;
    $.post(url, {"aid": id}, function(data, status){
        data = $.parseJSON(data) ;
        if(data.code == 1){
            location.href = "http://127.0.0.1:8000/alert" ;
        }else{
            alert("创建失败!失败原因：" + data.error) ;
        }
    }) ;
}

var show_code = function(id){
    var url = "http://127.0.0.1:8000/show_code?id=" + id ;
    location.href = url ;
}

