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
    $api->post('/user/message', 'App\Http\Controllers\Api\V1\LoginController@myMessage');
});
//私有接口需要登录
$api->version('v1', ['middleware' => 'jwt.auth'], function ($api) {
    $api -> post('authMe','App\Http\Controllers\Api\V1\LoginController@authMe');
    //办事
    $api->post('/event/myevent', 'App\Http\Controllers\Api\V1\LoginController@myEvent');
    $api->post('/event/myeventdetail', 'App\Http\Controllers\Api\V1\LoginController@myEventDetails');
    $api->post('/event/eventmark', 'App\Http\Controllers\Api\V1\LoginController@eventMark');
    $api->post('/event/selectexpert', 'App\Http\Controllers\Api\V1\LoginController@eventSelectExpert');
    $api->post('/event/eventapply', 'App\Http\Controllers\Api\V1\LoginController@eventApply');
    //咨询
    $api->post('/consult/myconsult', 'App\Http\Controllers\Api\V1\LoginController@myConsult');
    $api->post('/consult/myconsultdetail', 'App\Http\Controllers\Api\V1\LoginController@myConsultDetails');
    $api->post('/consult/consultmark', 'App\Http\Controllers\Api\V1\LoginController@consultMark');
    $api->post('/consult/selectexpert', 'App\Http\Controllers\Api\V1\LoginController@consultSelectExpert');
    $api->post('/consult/consultapply', 'App\Http\Controllers\Api\V1\LoginController@consultApply');
    //需求
    $api->post('/need/myneed', 'App\Http\Controllers\Api\V1\LoginController@myNeed');
    $api->post('/need/myneeddetail', 'App\Http\Controllers\Api\V1\LoginController@myNeedDetails');
    $api->post('/need/collect', 'App\Http\Controllers\Api\V1\LoginController@collectNeed');
    $api->post('/need/publish', 'App\Http\Controllers\Api\V1\LoginController@publishNeed');
    $api->post('/need/messageList', 'App\Http\Controllers\Api\V1\LoginController@messageListNeed');
    $api->post('/need/message', 'App\Http\Controllers\Api\V1\LoginController@messageNeed');
    //专家
    $api->post('/expert/myexpert', 'App\Http\Controllers\Api\V1\LoginController@myExpert');
    $api->post('/expert/myexpertdetail', 'App\Http\Controllers\Api\V1\LoginController@myExpertDetails');
    $api->post('/expert/collect', 'App\Http\Controllers\Api\V1\LoginController@collectExpert');
    $api->post('/expert/messageList', 'App\Http\Controllers\Api\V1\LoginController@messageListExpert');
    $api->post('/expert/message', 'App\Http\Controllers\Api\V1\LoginController@messageExpert');

    //企业认证
    $api->post('/company/register', 'App\Http\Controllers\Api\V1\LoginController@registerCompany');
    //专家认证
    $api->post('/expert/register', 'App\Http\Controllers\Api\V1\LoginController@registerExpert');
    //更改用户头像
    $api->post('/changeIcon', 'App\Http\Controllers\Api\V1\LoginController@changeIcon');
    //获取用户的账户余额信息
    $api->post('/getAccount', 'App\Http\Controllers\Api\V1\LoginController@getAccount');
    //收支明细
    $api->post('/accountDetails', 'App\Http\Controllers\Api\V1\LoginController@accountDetails');
    //提现操作
    $api->post('/withdrawals', 'App\Http\Controllers\Api\V1\LoginController@withdrawals');



});