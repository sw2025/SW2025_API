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
use PhpParser\Node\Expr\Empty_;

class LoginController extends Controller
{
    use Helpers;

    /**
     * 登录
     */
    function login()
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
    function register()
    {
        //要验证的数据
        $payload = app('request')->only('phone', 'password', 'verifycode', 'imei', 'role', 'action');
        // 验证的规则
        $rules = [
            'phone' => ['required', 'min:11', 'max:11'],
            'password' => ['required', 'min:6', 'max:16'],
            'verifycode' => ['required', 'min:6', 'max:6'],
            'role' => ['required'],
            'action' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        if ($payload['action'] == 'register') {
            //判断用户是否存在
            $user = User::where('phone', $payload['phone'])->first();
            if ($user) {
                return $this->response->array(['status_code' => '402', 'msg' => '用户已存在']);
            }
        }else if ($payload['action'] == 'forgot'){
            //判断用户是否存在
            $user = User::where('phone', $payload['phone'])->first();
            if (!$user) {
                return $this->response->array(['status_code' => '403', 'msg' => '用户不存在']);
            }
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
        if ($payload['action'] == 'register') {
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
        } else if ($payload['action'] == 'forgot') {
            $res = DB::table('t_u_user')
                ->where('phone', $payload['phone'])
                ->update([
                    'password' => bcrypt($payload['password']),
                    'imei' => $payload['imei'],
                ]);
            if (!$res){
                return $this->response->array(['status_code' => '501', 'msg' => '找回密码失败']);
            }else{
                $user = User::where('phone', $payload['phone'])->first();
                $token = JWTAuth::fromUser($user);
                return $this->response->array(['status_code' => '200', 'msg' => '找回密码成功', 'token' => $token]);
            }
        } else {
            return $this->response->array(['status_code' => '405', 'msg' => 'action参数错误']);
        }

    }

    /**
     * 获取用户手机验证码
     */
    function getSmsCode()
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
     * 我的系统消息接口
     */
    function myMessage(){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
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
     * 办事选择专家接口
     */
    function eventSelectExpert()
    {
        $payload = app('request')->only('eventid', 'expertid');
        $rules = [
            'eventid' => ['required'],
            'expertid' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_e_event')
            ->where('userid', $userId)
            ->where('eventid', $payload['eventid'])
            ->get();
        if (!$res) {
            return $this->response->array(['status_code' => '402', 'msg' => '未授权']);
        }
        $lds = explode(",", $payload['expertid']);
        $ben = DB::table('t_e_eventresponse')
            ->whereIn('expertid', array_filter($lds))
            ->where('eventid', $payload['eventid'])
            ->update(['state' => '3', "responsetime" => date("Y-m-d H:i:s", time())]);
        if ($ben) {
            return $this->response->array(['status_code' => '200', 'msg' => '修改成功']);
        } else {
            return $this->response->array(['status_code' => '402', 'msg' => '修改失败']);
        }
    }

    /**
     * 申请办事接口
     */
    function eventApply()
    {
        $payload = app('request')->only('type01', 'type02', 'brief', 'select', 'expert');
        $rules = [
            'type01' => ['required'],
            'type02' => ['required'],
            'brief' => ['required'],
            'select' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_e_event')
            ->insertGetId([
                'userid' => $userId,
                'domain1' => $payload['type01'],
                'domain2' => $payload['type02'],
                'brief' => $payload['brief'],
                'eventtime' => date("Y-m-d H:i:s"),
            ]);
        if (!$res) {
            return $this->response->array(['status_code' => '402', 'msg' => '数据插入失败']);
        } else {
            DB::table('t_e_eventverify')
                ->insert([
                    'eventid' => $res,
                    'configid' => '1',
                    'verifytime' => date("Y-m-d H:i:s"),
                ]);
            if ($payload['select'] != '0' && $payload['select'] != '1') {
                $select = '0';
            } else {
                $select = $payload['select'];
            }
            if ($select == 1) {
                if (empty($payload['expert'])) {
                    return $this->response->array(['status_code' => '403', 'msg' => '您未选择专家，默认选择系统分配']);
                } else {
                    $lds = explode(",", $payload['expert']);
                    foreach (array_filter($lds) as $ld) {
                        $ben = DB::table('t_u_expert')
                            ->where('expertid', $ld)
                            ->count();
                        if (!$ben) {
                            return $this->response->array(['status_code' => '403', 'msg' => '您未选择专家，默认选择系统分配']);
                        }
                    }
                    foreach (array_filter($lds) as $ld) {
                        DB::table('t_e_eventresponse')
                            ->insert([
                                'eventid' => $res,
                                'expertid' => $ld,
                                'state' => '1',
                                'responsetime' => date("Y-m-d H:i:s"),
                            ]);
                    }
                }
            }
            return $this->response->array(['status_code' => '200', 'msg' => '数据插入成功']);
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
     * 咨询选择专家接口
     */
    function consultSelectExpert()
    {
        $payload = app('request')->only('consultid', 'expertid');
        $rules = [
            'consultid' => ['required'],
            'expertid' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_c_consult')
            ->where('userid', $userId)
            ->where('consultid', $payload['consultid'])
            ->get();
        if (!$res) {
            return $this->response->array(['status_code' => '402', 'msg' => '未授权']);
        }
        $lds = explode(",", $payload['expertid']);
        $ben = DB::table('t_c_consultresponse')
            ->whereIn('expertid', array_filter($lds))
            ->where('consultid', $payload['consultid'])
            ->update([
                'state' => '3',
                "responsetime" => date("Y-m-d H:i:s", time())
            ]);
        if ($ben) {
            return $this->response->array(['status_code' => '200', 'msg' => '修改成功']);
        } else {
            return $this->response->array(['status_code' => '402', 'msg' => '修改失败']);
        }
    }

    /**
     * 申请咨询接口
     */
    function consultApply()
    {
        $payload = app('request')->only('type01', 'type02', 'brief', 'select', 'expert');
        $rules = [
            'type01' => ['required'],
            'type02' => ['required'],
            'brief' => ['required'],
            'select' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_c_consult')
            ->insertGetId([
                'userid' => $userId,
                'domain1' => $payload['type01'],
                'domain2' => $payload['type02'],
                'brief' => $payload['brief'],
                'consulttime' => date("Y-m-d H:i:s"),
            ]);
        if (!$res) {
            return $this->response->array(['status_code' => '402', 'msg' => '数据插入失败']);
        } else {
            DB::table('t_c_consultverify')
                ->insert([
                    'consultid' => $res,
                    'configid' => '1',
                    'verifytime' => date("Y-m-d H:i:s"),
                ]);
            if ($payload['select'] != '0' && $payload['select'] != '1') {
                $select = '0';
            } else {
                $select = $payload['select'];
            }
            if ($select == 1) {
                if (empty($payload['expert'])) {
                    return $this->response->array(['status_code' => '403', 'msg' => '您未选择专家，默认选择系统分配']);
                } else {
                    $lds = explode(",", $payload['expert']);
                    foreach (array_filter($lds) as $ld) {
                        $ben = DB::table('t_u_expert')
                            ->where('expertid', $ld)
                            ->count();
                        if (!$ben) {
                            return $this->response->array(['status_code' => '403', 'msg' => '您未选择专家，默认选择系统分配']);
                        }
                    }
                    foreach (array_filter($lds) as $ld) {
                        DB::table('t_c_consultresponse')
                            ->insert([
                                'consultid' => $res,
                                'expertid' => $ld,
                                'state' => '1',
                                'responsetime' => date("Y-m-d H:i:s"),
                            ]);
                    }
                }
            }
            return $this->response->array(['status_code' => '200', 'msg' => '数据插入成功']);
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
    function collectNeed()
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
     *  发布需求接口
     */
    function publishNeed()
    {
        $payload = app('request')->only('type01', 'type02', 'brief', 'needtype');
        $rules = [
            'type01' => ['required'],
            'type02' => ['required'],
            'brief' => ['required'],
            'needtype' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_n_need')
            ->insertGetId([
                'userid' => $userId,
                'domain1' => $payload['type01'],
                'domain2' => $payload['type02'],
                'brief' => $payload['brief'],
                'needtype' => $payload['needtype'],
                'needtime' => date("Y-m-d H:i:s"),
            ]);
        if (!$res) {
            return $this->response->array(['status_code' => '402', 'msg' => '数据插入失败']);
        } else {
            DB::table('t_n_needverify')
                ->insert([
                    'needid' => $res,
                    'configid' => '1',
                    'verifytime' => date("Y-m-d H:i:s"),
                ]);
            return $this->response->array(['status_code' => '200', 'msg' => '数据插入成功']);
        }
    }

    /**
     * 需求评论列表接口
     */
    function messageListNeed()
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
        $data = DB::table('t_n_messagetoneed')
            ->where('needid', $payload['needid'])
            ->where('parentid', 0)
            ->get();

        foreach ($data as $datas) {
            $id = $datas->id;
            $data01 = DB::table('t_n_messagetoneed')
                ->where('needid', $payload['needid'])
                ->where('parentid', $id)
                ->orderBy('messagetime', 'desc')
                ->get();
            $datas->benben = $data01;
        }
        return $this->response->array(['status_code' => '200', 'data' => $data]);

    }

    /**
     * 评论需求接口
     */
    function messageNeed()
    {
        $payload = app('request')->only('needid', 'parentid', 'use_userid', 'content');
        $rules = [
            'needid' => ['required'],
            'content' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $data = DB::table('t_n_messagetoneed')
            ->insert([
                'needid' => $payload['needid'],
                'parentid' => empty($payload['parentid']) ? '' : $payload['parentid'],
                'use_userid' => empty($payload['use_userid']) ? '' : $payload['use_userid'],
                'content' => $payload['content'],
                'userid' => $userId,
                'messagetime' => date("Y-m-d H:i:s", time()),
            ]);
        if (!$data) {
            return $this->response->array(['status_code' => '401', 'data' => '评论失败']);
        } else {
            return $this->response->array(['status_code' => '200', 'data' => '评论成功']);
        }
    }

    /**
     * 专家列表接口
     */
    function myExpert()
    {
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
    function myExpertDetails()
    {
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
    function collectExpert()
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

    /**
     * 专家评论列表接口
     */
    function messageListExpert()
    {
        $payload = app('request')->only('expertid');
        $rules = [
            'expertid' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $data = DB::table('t_u_messagetoexpert')
            ->where('expertid', $payload['expertid'])
            ->where('userid', $userId)
            ->orderBy('messagetime', 'desc')
            ->get();
        return $this->response->array(['status_code' => '200', 'data' => $data]);

    }

    /**
     * 评论专家接口
     */
    function messageExpert()
    {
        $payload = app('request')->only('expertid', 'content');
        $rules = [
            'expertid' => ['required'],
            'content' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $data = DB::table('t_u_messagetoexpert')
            ->insert([
                'expertid' => $payload['expertid'],
                'content' => $payload['content'],
                'userid' => $userId,
                'messagetime' => date("Y-m-d H:i:s", time()),
            ]);
        if (!$data) {
            return $this->response->array(['status_code' => '401', 'data' => '评论失败']);
        } else {
            return $this->response->array(['status_code' => '200', 'data' => '评论成功']);
        }

    }

    /**
     * 提交企业信息
     */
    function registerCompany()
    {
        $payload = app('request')->only('enterprisename', 'size', 'industry', 'address', 'licenceimage', 'showimage', 'brief');
        $rules = [
            'enterprisename' => ['required'],
            'size' => ['required'],
            'industry' => ['required'],
            'address' => ['required'],
            'licenceimage' => ['required'],
            'showimage' => ['required'],
            'brief' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_u_enterprise')
            ->insertGetId([
                'userid' => $userId,
                'enterprisename' => $payload['enterprisename'],
                'size' => $payload['size'],
                'industry' => $payload['industry'],
                'address' => $payload['address'],
                'licenceimage' => $payload['licenceimage'],
                'showimage' => $payload['showimage'],
                'brief' => $payload['brief'],
            ]);
        DB::table('t_u_enterpriseverify')
            ->insert([
                'enterpriseid' => $res,
                'configid' => '1',
                'verifytime' => date("Y-m-d H:i:s"),
            ]);
        $image_path = dirname(base_path()) . '/images/';
        if (!is_dir($image_path)) {
            mkdir($image_path, 0777, true);
        }
        foreach ($_FILES as $key => $file) {
            if (isset($_FILES[$key])) {
                $baseName = basename($file['name']);
                $extension = strrchr($baseName, ".");
                $newName = time() . mt_rand(1000, 9999) . $extension;
                $target_path = $image_path . $newName;
                $filePath = "/images/" . $newName;
                if (move_uploaded_file($_FILES[$key]["tmp_name"], $target_path)) {
                    $payload[$key] = $filePath;
                } else {
                    return $this->response->array(['status_code' => '401', 'msg' => "文件上传失败"]);
                }
            }
        }
        if ($res) {
            return $this->response->array(["status_code" => 200, "success_msg" => "注册成功"]);
        } else {
            return $this->response->array(["status_code" => 500, "error_msg" => "注册失败"]);
        }
    }

    /**
     * 提交专家信息
     */
    function registerExpert()
    {
        $payload = app('request')->only('expertname', 'category', 'address', 'licenceimage', 'showimage', 'brief', 'type01', 'type02');
        $rules = [
            'expertname' => ['required'],
            'category' => ['required'],
            'address' => ['required'],
            'licenceimage' => ['required'],
            'showimage' => ['required'],
            'type01' => ['required'],
            'type02' => ['required'],
            'brief' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_u_expert')
            ->insertGetId([
                'userid' => $userId,
                'expertname' => $payload['expertname'],
                'domain1' => $payload['type01'],
                'domain2' => $payload['type02'],
                'category' => $payload['category'],
                'address' => $payload['address'],
                'licenceimage' => $payload['licenceimage'],
                'showimage' => $payload['showimage'],
                'brief' => $payload['brief'],
            ]);
        DB::table('t_u_expertverify')
            ->insert([
                'enterpriseid' => $res,
                'configid' => '1',
                'verifytime' => date("Y-m-d H:i:s"),
            ]);
        $image_path = dirname(base_path()) . '/images/';
        if (!is_dir($image_path)) {
            mkdir($image_path, 0777, true);
        }
        foreach ($_FILES as $key => $file) {
            if (isset($_FILES[$key])) {
                $baseName = basename($file['name']);
                $extension = strrchr($baseName, ".");
                $newName = time() . mt_rand(1000, 9999) . $extension;
                $target_path = $image_path . $newName;
                $filePath = "/images/" . $newName;
                if (move_uploaded_file($_FILES[$key]["tmp_name"], $target_path)) {
                    $payload[$key] = $filePath;
                } else {
                    return $this->response->array(['status_code' => '401', 'msg' => "文件上传失败"]);
                }
            }
        }
        if ($res) {
            return $this->response->array(["status_code" => 200, "success_msg" => "注册成功"]);
        } else {
            return $this->response->array(["status_code" => 500, "error_msg" => "注册失败"]);
        }
    }

    /**
     * 更改用户头像
     */
    function changeIcon()
    {
        //返回路径中的目录部分
        $image_path = dirname(base_path()) . '/images/';
        //is_dir 是否是一个目录
        if (!is_dir($image_path)) {
            /**
             * 创建目录 成功true 失败false
             *
             * params1 规定要创建的目录的名称。
             * params2 规定权限。默认是 0777。
             * params3 规定是否设置递归模式。
             */
            mkdir($image_path, 0777, true);
        }
        //返回路径中的文件名部分 [name] 被上传文件的名称
        $baseName = basename($_FILES['avatar']['name']);
        //搜索 "." 在字符串中的位置，并返回从该位置到字符串结尾的所有字符：
        $extension = strrchr($baseName, ".");
        //mt_rand 生成1000-9999的随机数 生成新的名字 $newName
        $newName = time() . mt_rand(1000, 9999) . $extension;
        //图片的绝对路径存放区域
        $target_path = $image_path . $newName;
        $filePath = "/images/" . $newName;
        //将上传的文件移动到新位置 [tmp_name] 存储在服务器的文件的临时副本的名称
        if (move_uploaded_file($_FILES['avatar']['tmp_name'], $target_path)) {
            $user = JWTAuth::parseToken()->authenticate();
            $userid = $user['userid'];
            $dbs = DB::table("t_u_user")
                ->where("userid", $userid)
                ->update([
                    "avatar" => $filePath,
                    "updated_at" => date("Y-m-d H:i:s"),
                ]);
            if ($dbs) {
                return $this->response->array(['status_code' => '200', 'success' => '用户头像更新成功']);
            } else {
                return $this->response->array(['status_code' => '409', 'success' => '用户头像更新失败']);
            }
        }
        return $this->response->array(['status_code' => '200', 'success' => '用户头像更新失败']);
    }

    /**
     * 获取用户的账户余额信息
     */
    function getAccount()
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res01 = DB::table('t_u_bill')
            ->where('userid', $userId)
            ->where('type', '收入')
            ->sum('money');
        $res02 = DB::table('t_u_bill')
            ->where('userid', $userId)
            ->whereIn('type', ['支出', '在途'])
            ->sum('money');
        $ben = $res01 - $res02;
        if ($ben >= 0) {
            return $this->response->array(["status_code" => 200, 'balance' => $ben, 'income' => $res01, 'pay' => $res01]);
        } else {
            return $this->response->array(["status_code" => 200, 'data' => '个人数据异常']);
        }

    }

    /**
     * 收支明细
     */
    function accountDetails()
    {
        $payload = app('request')->only('type');
        $step = $payload['type'];
        $where = !empty($step) ? array("t_u_bill.type" => $step) : array();
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user['userid'];
        $res = DB::table('t_u_bill')
            ->where('userid', $userId)
            ->where($where)
            ->get();
        return $this->response->array(["status_code" => 200, 'balance' => $res]);
    }

    /**
     * 个人提现操作
     */
    function withdrawals()
    {
        $payload = app('request')->only('amount');
        $rules = [
            'amount' => ['required'],
        ];
        //构造验证器
        $validator = app('validator')->make($payload, $rules);
        if ($validator->fails()) {
            return $this->response->array(['status_code' => '401', 'msg' => $validator->errors()]);
        }
        if ($payload['amount'] < 0) {
            return $this->response->array(['status_code' => '402', 'msg' => '非法参数']);
        } else {
            $user = JWTAuth::parseToken()->authenticate();
            $userId = $user['userid'];
            $res01 = DB::table('t_u_bill')
                ->where('userid', $userId)
                ->where('type', '收入')
                ->sum('money');
            $res02 = DB::table('t_u_bill')
                ->where('userid', $userId)
                ->whereIn('type', ['支出', '在途'])
                ->sum('money');
            $ben = $res01 - $res02;
            if ($ben < 0) {
                return $this->response->array(['status_code' => '403', 'msg' => '个人数据异常']);
            } else {
                if ($ben < $payload['amount']) {
                    return $this->response->array(['status_code' => '404', 'msg' => '余额不足']);
                } else {
                    $res = DB::table('t_u_bill')
                        ->insert([
                            'userid' => $userId,
                            'type' => '3',
                            'channel' => '提现申请',
                            'billtime' => date("Y-m-d H:i:s"),
                        ]);
                    if (!$res) {
                        return $this->response->array(['status_code' => '405', 'msg' => '数据插入失败']);
                    } else {
                        return $this->response->array(['status_code' => '200', 'msg' => '提现成功']);
                    }
                }
            }
        }
    }


}
