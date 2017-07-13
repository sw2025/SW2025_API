<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It's a breeze. Simply tell Laravel the URIs it should respond to
| and give it the controller to call when that URI is requested.
|
*/

$api = app('Dingo\Api\Routing\Router');
//共有接口不需要登录
$api->version('v1', function ($api) {
    // 用户登录验证并返回 Token
    $api->post('/user/login', 'App\Http\Controllers\Api\V1\LoginController@login');
    $api->post('/user/register', 'App\Http\Controllers\Api\V1\LoginController@register');
    $api->post('/user/getSmsCode', 'App\Http\Controllers\Api\V1\LoginController@getSmsCode');
});
//私有接口需要登录
$api->version('v1', ['middleware' => 'jwt.auth'], function ($api) {
    $api -> post('authMe','App\Http\Controllers\Api\V1\LoginController@authMe');
    //办事
    $api->post('/event/myevent', 'App\Http\Controllers\Api\V1\LoginController@myEvent');
    $api->post('/event/myeventdetail', 'App\Http\Controllers\Api\V1\LoginController@myEventDetails');
    $api->post('/event/eventmark', 'App\Http\Controllers\Api\V1\LoginController@eventMark');
    //咨询
    $api->post('/consult/myconsult', 'App\Http\Controllers\Api\V1\LoginController@myConsult');
    $api->post('/consult/myconsultdetail', 'App\Http\Controllers\Api\V1\LoginController@myConsultDetails');
    $api->post('/consult/consultmark', 'App\Http\Controllers\Api\V1\LoginController@consultMark');
    //需求
    $api->post('/need/myneed', 'App\Http\Controllers\Api\V1\LoginController@myNeed');
    $api->post('/need/myneeddetail', 'App\Http\Controllers\Api\V1\LoginController@myNeedDetails');
    $api->post('/need/collect', 'App\Http\Controllers\Api\V1\LoginController@collectNeed');
    //专家
    $api->post('/expert/myexpert', 'App\Http\Controllers\Api\V1\LoginController@myExpert');
    $api->post('/expert/myexpertdetail', 'App\Http\Controllers\Api\V1\LoginController@myExpertDetails');
    $api->post('/expert/collect', 'App\Http\Controllers\Api\V1\LoginController@collectExpert');
});