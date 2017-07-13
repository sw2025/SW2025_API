<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests;
use App\Service;
use App\User;
use Cache;
use DB;
use Dingo\Api\Routing\Helpers;
use JWTAuth;

class LoginController extends Controller
{
    use Helpers;

    /**
     * 登录
     */
    public function login()
    {
        //要验证的数据
        $payload = app('request')->only('phone', 'password', 'imei');
        // 验证的规则
        $rules = [
            'phone' => ['required', 'min:11', 'max:11'],
            'password' => ['required', 'min:6', 'max:16'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        //验证手机号是否存在
        $user = User::where('phone', $payload['phone'])->first();
        if (!$user) {
            return $this->response->array(['status_code' => '406', 'msg' => '手机号未注册']);
        }
        //判断用户状态是否冻结，如果冻结，不能登录 0：正常状态  1：被冻结
        if ($user->state == 1) {
            return $this->response->array(['status_code' => '403', 'msg' => '被冻结']);
        }
        //更新user表的imei
        DB::table('t_u_user')->where("phone", $payload['phone'])->update([
            'imei' => $payload['imei']
        ]);
        $token = JWTAuth::fromUser($user);
        return $this->response->array(['status_code' => '200', 'token' => $token]);
    }

    /**
     * 注册
     */
    public function register()
    {
        //要验证的数据
        $payload = app('request')->only('phone', 'password', 'verifycode', 'imei', 'role');
        // 验证的规则
        $rules = [
            'phone' => ['required', 'min:11', 'max:11'],
            'password' => ['required', 'min:6', 'max:16'],
            'verifycode' => ['required', 'min:6', 'max:6'],
            'role' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);

        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        //判断用户是否存在
        $user = User::where('phone', $payload['phone'])->first();
        if ($user) {
            return $this->response->array(['status_code' => '402', 'msg' => '用户已存在']);
        }
        // 手机验证码验证
        if (Cache::has($payload['phone'])) {
            $smscode = Cache::get($payload['phone']);
            if ($smscode != $payload['verifycode']) {
                return $this->response->array(['status_code' => '404', 'msg' => '手机验证码错误']);
            }
        } else {
            return $this->response->array(['status_code' => '404', 'msg' => '手机验证码错误']);
        }
        $res = DB::table('t_u_user')->insert([
            'phone' => $payload['phone'],
            'password' => bcrypt($payload['password']),
            'imei' => $payload['imei'],
            'registertime' => date("Y-m-d H:i:s"),
        ]);
        // 创建用户成功
        if ($res) {
            $user = User::where('phone', $payload['phone'])->first();
            if ($payload['role'] == 'expert') {
                DB::table('t_u_expert')->insert(['userid' => $user['userid']]);
            } else if ($payload['role'] == 'enterprise') {
                DB::table('t_u_enterprise')->insert(['userid' => $user['userid']]);
            }
            //生成token
            $token = JWTAuth::fromUser($user);
            return $this->response->array(['status_code' => '200', 'msg' => '创建用户成功', 'token' => $token]);
        } else {
            return $this->response->array(['status_code' => '501', 'msg' => '创建用户失败']);
        }
    }

    /**
     * 获取用户手机验证码
     */
    public function getSmsCode()
    {
        // 获取手机号码
        $payload = app('request')->only('phone', 'action');
        $phone = $payload['phone'];
        // 验证的规则
        $rules = [
            'phone' => ['required', 'min:11', 'max:11'],
            'action' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        if ($payload['action'] == 'forgot') {
            //验证手机号是否存在
            $user = User::where('phone', $payload['phone'])->first();
            if (!$user) {
                return $this->response->array(['status_code' => '406', 'msg' => '手机号不存在']);
            }
            //判断用户状态是否冻结，如果冻结，不能登录 0：正常状态  1：被冻结
            if ($user->state == 1) {
                return $this->response->array(['status_code' => '404', 'msg' => '被冻结']);
            }
        }
        $randNum = $this->__randStr(6, 'NUMBER');
        // 验证码存入缓存 20 分钟
        $expiresAt = 20;
        Cache::put($phone, $randNum, $expiresAt);
        header('content-type:text/html;charset=utf-8');
        $sendUrl = 'http://v.juhe.cn/sms/send'; //短信接口的URL
        $smsConf = array(
            'key' => env('JHSMS_APPKEY'), //您申请的APPKEY
            'mobile' => $phone, //接受短信的用户手机号码
            'tpl_id' => '26613', //您申请的短信模板ID，根据实际情况修改
            'tpl_value' => '#code#=' . $randNum //您设置的模板变量，根据实际情况修改
        );
        $content = $this->juhecurl($sendUrl, $smsConf, 1); //请求发送短信
        if ($content) {
            $result = json_decode($content, true);
            $error_code = $result['error_code'];
            if ($error_code == 0) {
                //状态为0，说明短信发送成功
                return $this->response->array(['status_code' => '200', 'msg' => 'Send Sms Success']);
            } else {
                //状态非0，说明失败
                $msg = $result['reason'];
                return $this->response->array(['status_code' => '503', 'msg' => $msg]);
            }
        } else {
            //返回内容异常，以下可根据业务逻辑自行修改
            return $this->response->array(['status_code' => '503', 'msg' => 'Send Sms Error']);
        }
    }

    /**
     * 随机产生六位数
     *
     * @param int $len
     * @param string $format
     * @return string
     */
    public function __randStr($len = 6, $format = 'ALL')
    {
        switch ($format) {
            case 'ALL':
                $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-@#~';
                break;
            case 'CHAR':
                $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-@#~';
                break;
            case 'NUMBER':
                $chars = '0123456789';
                break;
            default :
                $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-@#~';
                break;
        }
        mt_srand((double)microtime() * 1000000 * getmypid());
        $password = "";
        while (strlen($password) < $len)
            $password .= substr($chars, (mt_rand() % strlen($chars)), 1);
        return $password;
    }

    /**
     * 请求接口返回内容
     * @param  string $url [请求的URL地址]
     * @param  string $params [请求的参数]
     * @param  int $ipost [是否采用POST形式]
     * @return  string
     */
    function juhecurl($url, $params = false, $ispost = 0)
    {
        $httpInfo = array();
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22');
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if ($ispost) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
            curl_setopt($ch, CURLOPT_URL, $url);
        } else {
            if ($params) {
                curl_setopt($ch, CURLOPT_URL, $url . '?' . $params);
            } else {
                curl_setopt($ch, CURLOPT_URL, $url);
            }
        }
        $response = curl_exec($ch);
        if ($response === FALSE) {
            //echo "cURL Error: " . curl_error($ch);
            return false;
        }
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $httpInfo = array_merge($httpInfo, curl_getinfo($ch));
        curl_close($ch);
        return $response;
    }

    /**
     * 获取用户名的基本信息
     */
    function authMe()
    {
        $user = JWTAuth::parseToken()->authenticate();
        return array(['status_code' => '200', 'user' => $user]);
    }

    /**
     * 办事列表接口
     */
    function myEvent()
    {
        $payload = app('request')->only('step', 'order');
        $order = $payload['order'];
        if ($payload['order'] != 'desc' && $payload['order'] != 'asc') {
            $order = 'desc';
        }
        $step = $payload['step'];
        if ($payload['step'] != '1' && $payload['step'] != '2' && $payload['step'] != '3' && $payload['step'] != '4' &&
            $payload['step'] != '5' && $payload['step'] != '6' && $payload['step'] != '7' && $payload['step'] != '8'
        ) {
            $step = '';
        }
        $where = !empty($step) ? array("t_e_eventverify.configid" => $step) : array();
        $user = JWTAuth::parseToken()->authenticate();
        $userid = $user['userid'];
        $data = DB::table('t_e_event')
            ->leftJoin("t_e_eventverify", "t_e_eventverify.eventid", "=", "t_e_event.eventid")
            ->leftJoin("t_e_eventverifyconfig", "t_e_eventverify.configid", "=", "t_e_eventverifyconfig.configid")
            ->whereRaw('t_e_eventverify.id in (select max(id) from t_e_eventverify group by  t_e_eventverify.eventid)')
            ->where("userid", $userid)
            ->orderBy('verifytime', $order)
            ->where($where)
            ->get();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 办事详情接口
     */
    function myEventDetails()
    {
        $payload = app('request')->only('eventid');
        $rules = [
            'eventid' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $eventid = $payload['eventid'];
        $data = DB::table('t_e_event')
            ->leftJoin("t_e_eventverify", "t_e_eventverify.eventid", "=", "t_e_event.eventid")
            ->leftJoin("t_e_eventverifyconfig", "t_e_eventverify.configid", "=", "t_e_eventverifyconfig.configid")
            ->orderBy('verifytime', 'desc')
            ->where("t_e_event.eventid", $eventid)
            ->get();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 办事评价接口
     */
    function eventMark()
    {
        $payload = app('request')->only('eventid', 'expertid', 'score', 'comment');
        $rules = [
            'eventid' => ['required'],
            'expertid' => ['required'],
            'score' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $res = DB::table('t_e_eventtcomment')->insert([
            'eventid' => $payload['eventid'],
            'expertid' => $payload['expertid'],
            'score' => $payload['score'],
            'comment' => $payload['comment'],
            'commenttime' => date("Y-m-d H:i:s"),
        ]);
        if ($res) {
            return $this->response->array(['status_code' => '200', 'msg' => '评价成功']);
        } else {
            return $this->response->array(['status_code' => '501', 'msg' => '评价失败']);
        }
    }

    /**
     * 咨询列表接口
     */
    function myConsult()
    {
        $payload = app('request')->only('step', 'order');
        $order = $payload['order'];
        if ($payload['order'] != 'desc' && $payload['order'] != 'asc') {
            $order = 'desc';
        }
        $step = $payload['step'];
        if ($payload['step'] != '1' && $payload['step'] != '2' && $payload['step'] != '3' && $payload['step'] != '4' &&
            $payload['step'] != '5' && $payload['step'] != '6' && $payload['step'] != '7' && $payload['step'] != '8'
        ) {
            $step = '';
        }
        $where = !empty($step) ? array("t_e_consultverify.configid" => $step) : array();
        $user = JWTAuth::parseToken()->authenticate();
        $userid = $user['userid'];
        $data = DB::table('t_c_consult')
            ->leftJoin("t_c_consultverify", "t_c_consultverify.consultid", "=", "t_c_consult.consultid")
            ->leftJoin("t_c_consultverifyconfig", "t_c_consultverify.configid", "=", "t_c_consultverifyconfig.configid")
            ->whereRaw('t_c_consultverify.id in (select max(id) from t_c_consultverify group by  t_c_consultverify.consultid)')
            ->where("userid", $userid)
            ->orderBy('verifytime', $order)
            ->where($where)
            ->get();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 咨询详情接口
     */
    function myConsultDetails()
    {
        $payload = app('request')->only('consultid');
        $rules = [
            'consultid' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $consultid = $payload['consultid'];

        $data = DB::table('t_c_consult')
            ->leftJoin("t_c_consultverify", "t_c_consultverify.consultid", "=", "t_c_consult.consultid")
            ->leftJoin("t_c_consultverifyconfig", "t_c_consultverify.configid", "=", "t_c_consultverifyconfig.configid")
            ->orderBy('verifytime', 'desc')
            ->where("t_c_consult.consultid", $consultid)
            ->get();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 咨询评价接口
     */
    function consultMark()
    {
        $payload = app('request')->only('consultid', 'expertid', 'score', 'comment');
        $rules = [
            'consultid' => ['required'],
            'expertid' => ['required'],
            'score' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $res = DB::table('t_c_consultcomment')->insert([
            'consultid' => $payload['consultid'],
            'expertid' => $payload['expertid'],
            'score' => $payload['score'],
            'comment' => $payload['comment'],
            'commenttime' => date("Y-m-d H:i:s"),
        ]);
        if ($res) {
            return $this->response->array(['status_code' => '200', 'msg' => '评价成功']);
        } else {
            return $this->response->array(['status_code' => '501', 'msg' => '评价失败']);
        }
    }

    /**
     * 需求列表接口
     */
    function myNeed()
    {
        $payload = app('request')->only('type01', 'type02', 'order');
        $order = $payload['order'];
        if ($payload['order'] != 'desc' && $payload['order'] != 'asc') {
            $order = 'desc';
        }

        $type01 = !empty($payload['type01']) ? array("t_n_need.domain1" => $payload['type01']) : array();
        $type02 = !empty($payload['type02']) ? array("t_n_need.domain2" => $payload['type02']) : array();

        $user = JWTAuth::parseToken()->authenticate();
        $userid = $user['userid'];
        $data = DB::table('t_n_need')
            ->leftJoin("t_n_needverify", "t_n_needverify.needid", "=", "t_n_need.needid")
            ->leftJoin("t_n_needverifyconfig", "t_n_needverifyconfig.configid", "=", "t_n_needverify.configid")
            ->whereRaw('t_n_needverify.id in (select max(id) from t_n_needverify group by  t_n_needverify.needid)')
            ->where("userid", $userid)
            ->where($type01)
            ->where($type02)
            ->orderBy('verifytime', $order)
            ->get();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 需求详情接口
     */
    function myNeedDetails()
    {
        $payload = app('request')->only('needid');
        $rules = [
            'needid' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $needid = $payload['needid'];

        $data = DB::table('t_n_need')
            ->leftJoin("t_n_needverify", "t_n_needverify.needid", "=", "t_n_need.needid")
            ->leftJoin("t_n_needverifyconfig", "t_n_needverify.configid", "=", "t_n_needverifyconfig.configid")
            ->orderBy('verifytime', 'desc')
            ->where("t_n_need.needid", $needid)
            ->first();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 收藏需求接口
     */
    public function collectNeed()
    {
        $payload = app("request")->only('needid');
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $counts = DB::table('t_n_collectneed')->where("userid", $userId)->where("needid", $payload['needid'])->count();
        if ($counts) {
            $remark = DB::table('t_n_collectneed')
                ->where("userid", $userId)
                ->where("needid", $payload['needid'])
                ->pluck('remark');
            if ($remark == 0) {
                $res = DB::table('t_n_collectneed')
                    ->where("userid", $userId)
                    ->where("needid", $payload['needid'])
                    ->update([
                        "remark" => 1,
                        "collecttime" => date("Y-m-d H:i:s", time()),
                    ]);
                if ($res) {
                    return $this->response->array(["status_code" => 200, "success_msg" => "收藏成功"]);
                } else {
                    return $this->response->array(["status_code" => 500, "error_msg" => "收藏失败"]);
                }
            } else {
                $res = DB::table('t_n_collectneed')
                    ->where("userid", $userId)
                    ->where("needid", $payload['needid'])
                    ->update([
                        "remark" => 0,
                        "collecttime" => date("Y-m-d H:i:s", time()),
                    ]);
                if ($res) {
                    return $this->response->array(["status_code" => 200, "success_msg" => "取消收藏成功"]);
                } else {
                    return $this->response->array(["status_code" => 500, "error_msg" => "取消收藏失败"]);
                }
            }
        } else {
            $res = DB::table('t_n_collectneed')->insert([
                "userid" => $userId,
                "needid" => $payload['needid'],
                "remark" => 1,
                "collecttime" => date("Y-m-d H:i:s", time()),
            ]);
            if ($res) {
                return $this->response->array(["status_code" => 200, "success_msg" => "收藏成功"]);
            } else {
                return $this->response->array(["status_code" => 500, "error_msg" => "收藏失败"]);
            }
        }
    }

    /**
     * 专家列表接口
     */
    function myExpert(){
        $payload = app('request')->only('type01', 'type02', 'order');
        $order = $payload['order'];
        if ($payload['order'] != 'desc' && $payload['order'] != 'asc') {
            $order = 'desc';
        }

        $type01 = !empty($payload['type01']) ? array("t_u_expert.domain1" => $payload['type01']) : array();
        $type02 = !empty($payload['type02']) ? array("t_u_expert.domain2" => $payload['type02']) : array();

        $user = JWTAuth::parseToken()->authenticate();
        $userid = $user['userid'];
        $data = DB::table('t_u_expert')
            ->leftJoin("t_u_expertverify", "t_u_expertverify.expertid", "=", "t_u_expert.expertid")
            ->leftJoin("t_u_expertverifyconfig", "t_u_expertverifyconfig.configid", "=", "t_u_expertverify.configid")
            ->whereRaw('t_u_expertverify.id in (select max(id) from t_u_expertverify group by  t_u_expertverify.expertid)')
            ->where("userid", $userid)
            ->where($type01)
            ->where($type02)
            ->orderBy('verifytime', $order)
            ->get();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 专家详情接口
     */
    function myExpertDetails(){
        $payload = app('request')->only('expertid');
        $rules = [
            'expertid' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $expertid = $payload['expertid'];

        $data = DB::table('t_u_expert')
            ->leftJoin("t_u_expertverify", "t_u_expertverify.expertid", "=", "t_u_expert.expertid")
            ->leftJoin("t_u_expertverifyconfig", "t_u_expertverify.configid", "=", "t_u_expertverifyconfig.configid")
            ->orderBy('verifytime', 'desc')
            ->where("t_u_expert.expertid", $expertid)
            ->first();
        return $this->response->array([
            'status_code' => '200',
            'data' => $data,
        ]);
    }

    /**
     * 收藏专家接口
     */
    public function collectExpert()
    {
        $payload = app("request")->only('expertid');
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $counts = DB::table('t_u_collectexpert')->where("userid", $userId)->where("expertid", $payload['expertid'])->count();
        if ($counts) {
            $remark = DB::table('t_u_collectexpert')
                ->where("userid", $userId)
                ->where("expertid", $payload['expertid'])
                ->pluck('remark');
            if ($remark == 0) {
                $res = DB::table('t_u_collectexpert')
                    ->where("userid", $userId)
                    ->where("expertid", $payload['expertid'])
                    ->update([
                        "remark" => 1,
                        "collecttime" => date("Y-m-d H:i:s", time()),
                    ]);
                if ($res) {
                    return $this->response->array(["status_code" => 200, "success_msg" => "收藏成功"]);
                } else {
                    return $this->response->array(["status_code" => 500, "error_msg" => "收藏失败"]);
                }
            } else {
                $res = DB::table('t_u_collectexpert')
                    ->where("userid", $userId)
                    ->where("expertid", $payload['expertid'])
                    ->update([
                        "remark" => 0,
                        "collecttime" => date("Y-m-d H:i:s", time()),
                    ]);
                if ($res) {
                    return $this->response->array(["status_code" => 200, "success_msg" => "取消收藏成功"]);
                } else {
                    return $this->response->array(["status_code" => 500, "error_msg" => "取消收藏失败"]);
                }
            }
        } else {
            $res = DB::table('t_u_collectexpert')->insert([
                "userid" => $userId,
                "expertid" => $payload['expertid'],
                "remark" => 1,
                "collecttime" => date("Y-m-d H:i:s", time()),
            ]);
            if ($res) {
                return $this->response->array(["status_code" => 200, "success_msg" => "收藏成功"]);
            } else {
                return $this->response->array(["status_code" => 500, "error_msg" => "收藏失败"]);
            }
        }
    }
}
