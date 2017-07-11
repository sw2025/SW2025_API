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
    $api->post('/benben01', 'App\Http\Controllers\Api\V1\BenController@benben01');
});
//私有接口需要登录
$api->version('v1', ['middleware' => 'jwt.auth'], function ($api) {
    
});