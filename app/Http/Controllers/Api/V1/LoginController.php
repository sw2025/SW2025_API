<?php

namespace App\Http\Controllers\Api\V1;

use Dingo\Api\Routing\Helpers;
use Illuminate\Http\Request;

use App\Http\Requests;
use App\Http\Controllers\Controller;

class LoginController extends Controller
{
    use Helpers;
    public function register()
    {
        // 验证规则
        $rules = [
            'phonenumber' => ['required', 'min:11', 'max:11', 'unique:users'],
            'password' => ['required', 'min:6'],
            'smscode' => ['required', 'min:6']
        ];

        $payload = app('request')->all();
        $validator = app('validator')->make($payload, $rules);

        // 手机验证码验证
        if (Cache::has($payload['phonenumber'])) {
            $smscode = Cache::get($payload['phonenumber']);
            if ($smscode != $payload['smscode']) {
                return $this->response->array(['status_code' => '402', 'msg' => 'phonenumber smscode error']);//402 手机或者验证码错误，401数据格式验证不通过，501服务端错误，403手机验证码发送失败,404登录失败
            }
        } else {
            return $this->response->array(['status_code' => '402', 'msg' => 'phonenumber smscode error']);
        }

        // 验证格式
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }

        $Channel = isset($payload['Channel'])? $payload['Channel'] : '';

        // 创建用户
        $res = User::insert([
            'phonenumber' => $payload['phonenumber'],
            'Channel' => $Channel,
            'password' => bcrypt($payload['password']),
            "created_at"=>date("Y-m-d H:i:s",time()),
            "updated_at"=>date("Y-m-d H:i:s",time()),
        ]);

        // 创建用户成功
        if ($res) {
            /*//给客服发送邮件
            $phonenumber = $payload['phonenumber'];

            $fp = fsockopen("paper.zerdream.com", 80, $errno, $errstr, 30);
            if ($fp) {
                $header  = "GET /v1/sendmail?access_token=token&phonenumber=$phonenumber HTTP/1.1\r\n";
                $header .= "Host: dailyapi.ziyawang.com\r\n";
                $header .= "Connection: Close\r\n\r\n";//长连接关闭
                fwrite($fp, $header);
                fclose($fp);
            }*/

            //生成token
            $user = User::where('phonenumber', $payload['phonenumber'])->first();
            $token = JWTAuth::fromUser($user);
            $IM = new IMController();
            $IM->get_rongcloud_token($user->userid);
            return $this->response->array(['status_code' => '200', 'msg' => 'Create User Success', 'token' => $token, 'role' => '0', 'UserID' => $user->userid, 'UserPicture' => $user->UserPicture,]);
        } else {
            return $this->response->array(['status_code' => '501', 'msg' => 'Create User Error']);
        }
    }

    /**
     * 获取用户手机验证码
     * @parameter $phonenumber $action(register&&login)
     */
    public function getSmsCode()
    {// 获取手机号码
        $payload = app('request')->only('phonenumber');
        $phonenumber = $payload['phonenumber'];

        $action = app('request')->get('action');
        if ($action == 'register') {
            $user = User::where('phonenumber', $payload['phonenumber'])->first();
            if($user) {
                return $this->response->array(['status_code' => '405', 'msg' => 'phonenumber is exist']);
            }
        } elseif ($action == 'login') {
            $user = User::where('phonenumber', $payload['phonenumber'])->first();
            if(!$user) {
                return $this->response->array(['status_code' => '406', 'msg' => 'phonenumber does not exist']);
            }
        } else {
            return $this->response->array(['status_code' => '401', 'msg' => 'lose argument action']);
        }


        // 获取验证码
        $randNum = $this->__randStr(6, 'NUMBER');

        // 验证码存入缓存 10 分钟
        $expiresAt = 20;

        Cache::put($phonenumber, $randNum, $expiresAt);

        // // 短信内容
        // $smsTxt = '验证码为：' . $randNum . '，请在 10 分钟内使用！';

        // 发送验证码短信
        $res = $this->_sendSms($phonenumber, $randNum, $action);

        // 发送结果
        if ($res) {
            return $this->response->array(['status_code' => '200', 'msg' => 'Send Sms Success']);
        } else {
            return $this->response->array(['status_code' => '503', 'msg' => 'Send Sms Error']);
        }
    }


    /**
     * 登录验证
     * @param Request $request $phonenumber $password
     * @return mixed
     */
    public function login(Request $request){
        // 验证规则
        $rules = [
            'phonenumber' => ['required', 'min:11', 'max:11'],
            'password' => ['required', 'min:6'],
        ];

        //验证格式
        $payload = app('request')->only('phonenumber', 'password');

        $validator = app('validator')->make($payload, $rules);
        // 验证格式
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }


        //验证手机号是否存在
        $user = User::where('phonenumber', $payload['phonenumber'])->first();
        if(!$user) {
            return $this->response->array(['status_code' => '406', 'msg' => 'phonenumber does not exist']);
        }
        //判断用户状态是否冻结，如果冻结，不能登录
        if($user->Status == 1) {
            return $this->response->array(['status_code' => '405', 'msg' => 'illegal operation']);
        }

        // grab credentials from the request
        $credentials = $request->only('phonenumber', 'password');
        try {
            // attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
                // return response()->json(['error' => 'invalid_credentials'], 401);
                return $this->response->array(['status_code' => '404', 'msg' => 'invalid_credentials']);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return $this->response->array(['status_code' => '502', 'msg' => 'could_not_create_token']);
        }
        $IM = new IMController();
        $IM->get_rongcloud_token($user->userid);
        return $this->response->array(['status_code' => '200', 'token' => $token, 'UserID' => $user->userid, 'UserPicture' => $user->UserPicture]);


    }

    /**
     * 忘记密码
     * @parameter $phonenumber  $password $smscode
     * @return mixed
     */
    public function resetPassword()
    {
        // 验证规则
        $rules = [
            'phonenumber' => ['required', 'min:11', 'max:11'],
            'password' => ['required', 'min:6'],
            'smscode' => ['required', 'min:6']
        ];

        $payload = app('request')->only('phonenumber', 'password', 'smscode');
        $validator = app('validator')->make($payload, $rules);

        // 手机验证码验证
        if (Cache::has($payload['phonenumber'])) {
            $smscode = Cache::get($payload['phonenumber']);

            if ($smscode != $payload['smscode']) {
                return $this->response->array(['status_code' => '402', 'msg' => 'phonenumber smscode error']);
            }
        } else {
            return $this->response->array(['status_code' => '402', 'msg' => 'phonenumber smscode error']);
        }

        // 验证格式
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }

        $user = User::where('phonenumber', $payload['phonenumber'])->first();
        $user->password = bcrypt($payload['password']);
        $res = $user->save();
        // 发送结果
        if ($res) {
            // 通过用户实例，获取jwt-token
            try{
                $token = JWTAuth::fromUser($user);
                $IM = new IMController();
                $IM->get_rongcloud_token($user->userid);
            }catch(JWTException $e){
                return $this->response->array(['status_code' => '502', 'msg' => 'could_not_create_token']);
            }
            return $this->response->array(['status_code' => '200', 'token' => $token,'UserID' => $user->userid, 'UserPicture' => $user->UserPicture,]);
        } else {
            return $this->response->array(['status_code' => '504', 'msg' => 'Password Change Error']);
        }
    }

}
