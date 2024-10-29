<?php

namespace Tencent;

if ( version_compare( PHP_VERSION, '5.1.2' ) < 0 ) {
    trigger_error( 'need php 5.1.2 or newer', E_USER_ERROR );
}

class TLSSigAPIv2 {

    private $key = false;
    private $sdkappid = 0;

    /**
     * Function: Used to issue UserSig that is required by the TRTC and CHAT services.
     *
     * Parameter description:
     * @param userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
     * @param expire - UserSig expiration time, in seconds. For example, 86400 indicates that the generated UserSig will expire one day after being generated.
     * @return string signature string
     * @throws \Exception
    */

    public function genUserSig( $userid, $expire = 86400*180 ) {
        return $this->__genSig( $userid, $expire, '', false );
    }

    /**
     * Function:
     * Used to issue PrivateMapKey that is optional for room entry.
     * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
     *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
     *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
     * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
     *
     * Parameter description:
     * userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
     * roomid - ID of the room to which the specified UserID can enter.
     * expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
     * privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
     *  - Bit 1: 0000 0001 = 1, permission for room creation
     *  - Bit 2: 0000 0010 = 2, permission for room entry
     *  - Bit 3: 0000 0100 = 4, permission for audio sending
     *  - Bit 4: 0000 1000 = 8, permission for audio receiving
     *  - Bit 5: 0001 0000 = 16, permission for video sending
     *  - Bit 6: 0010 0000 = 32, permission for video receiving
     *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
     *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
     *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
     *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
     */

    public function genPrivateMapKey( $userid, $expire, $roomid, $privilegeMap ) {
        $userbuf = $this->__genUserBuf( $userid, $roomid, $expire, $privilegeMap, 0, '' );
        return $this->__genSig( $userid, $expire, $userbuf, true );
    }
    
    /**
     * Function:
     * Used to issue PrivateMapKey that is optional for room entry.
     * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
     *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
     *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
     * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
     *
     * Parameter description:
     * @param userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
     * @param roomstr - ID of the room to which the specified UserID can enter.
     * @param expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
     * @param privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
     *  - Bit 1: 0000 0001 = 1, permission for room creation
     *  - Bit 2: 0000 0010 = 2, permission for room entry
     *  - Bit 3: 0000 0100 = 4, permission for audio sending
     *  - Bit 4: 0000 1000 = 8, permission for audio receiving
     *  - Bit 5: 0001 0000 = 16, permission for video sending
     *  - Bit 6: 0010 0000 = 32, permission for video receiving
     *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
     *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
     *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
     *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
     */

    public function genPrivateMapKeyWithStringRoomID( $userid, $expire, $roomstr, $privilegeMap ) {
        $userbuf = $this->__genUserBuf( $userid, 0, $expire, $privilegeMap, 0, $roomstr );
        return $this->__genSig( $userid, $expire, $userbuf, true );
    }

    public function __construct( $sdkappid, $key ) {
        $this->sdkappid = $sdkappid;
        $this->key = $key;
    }

    /**
    * base64 encode for url
    * '+' => '*', '/' => '-', '=' => '_'
    * @param string $string data to be encoded
    * @return string The encoded base64 string, returns false on failure
    * @throws \Exception
    */
    private function base64_url_encode( $string ) {
        static $replace = Array( '+' => '*', '/' => '-', '=' => '_' );
        $base64 = base64_encode( $string );
        if ( $base64 === false ) {
            throw new \Exception( 'base64_encode error' );
        }
        return str_replace( array_keys( $replace ), array_values( $replace ), $base64 );
    }

    /**
    * base64 decode for url
    * '+' => '*', '/' => '-', '=' => '_'
    * @param string $base64 base64 string to be decoded
    * @return string Decoded data, return false on failure
    * @throws \Exception
    */
    private function base64_url_decode( $base64 ) {
        static $replace = Array( '+' => '*', '/' => '-', '=' => '_' );
        $string = str_replace( array_values( $replace ), array_keys( $replace ), $base64 );
        $result = base64_decode( $string );
        if ( $result == false ) {
            throw new \Exception( 'base64_url_decode error' );
        }
        return $result;
    }
    
    /**
    * User-defined userbuf is used for the encrypted string of TRTC service entry permission
    * @brief generate userbuf
    * @param account username
    * @param dwSdkappid sdkappid
    * @param dwAuthID  digital room number
    * @param dwExpTime Expiration time: The expiration time of the encrypted string of this permission. Expiration time = now+dwExpTime
    * @param dwPrivilegeMap User permissions, 255 means all permissions
    * @param dwAccountType User type, default is 0
    * @param roomStr String room number
    * @return userbuf string  returned userbuf
    */

    private function __genUserBuf( $account, $dwAuthID, $dwExpTime, $dwPrivilegeMap, $dwAccountType,$roomStr ) {
     
        //cVer  unsigned char/1 版本号，填0
        if($roomStr == '')
            $userbuf = pack( 'C1', '0' );
        else
            $userbuf = pack( 'C1', '1' );
        
        $userbuf .= pack( 'n', strlen( $account ) );
        //wAccountLen   unsigned short /2   第三方自己的帐号长度
        $userbuf .= pack( 'a'.strlen( $account ), $account );
        //buffAccount   wAccountLen 第三方自己的帐号字符
        $userbuf .= pack( 'N', $this->sdkappid );
        //dwSdkAppid    unsigned int/4  sdkappid
        $userbuf .= pack( 'N', $dwAuthID );
        //dwAuthId  unsigned int/4  群组号码/音视频房间号
        $expire = $dwExpTime + time();
        $userbuf .= pack( 'N', $expire );
        //dwExpTime unsigned int/4  过期时间 （当前时间 + 有效期（单位：秒，建议300秒））
        $userbuf .= pack( 'N', $dwPrivilegeMap );
        //dwPrivilegeMap unsigned int/4  权限位
        $userbuf .= pack( 'N', $dwAccountType );
        //dwAccountType  unsigned int/4
        if($roomStr != '')
        {
            $userbuf .= pack( 'n', strlen( $roomStr ) );
            //roomStrLen   unsigned short /2   字符串房间号长度
            $userbuf .= pack( 'a'.strlen( $roomStr ), $roomStr );
            //roomStr   roomStrLen 字符串房间号
        }
        return $userbuf;
    }
    
    /**
    * Use hmac sha256 to generate sig field content, base64 encoded
    * @param $identifier Username, utf-8 encoded
    * @param $curr_time The unix timestamp of the current generated sig
    * @param $expire Validity period, in seconds
    * @param $base64_userbuf base64 encoded userbuf
    * @param $userbuf_enabled 是No enable userbuf
    * @return string sig after base64
    */
    private function hmacsha256( $identifier, $curr_time, $expire, $base64_userbuf, $userbuf_enabled ) {
        $content_to_be_signed = 'TLS.identifier:' . $identifier . "\n"
        . 'TLS.sdkappid:' . $this->sdkappid . "\n"
        . 'TLS.time:' . $curr_time . "\n"
        . 'TLS.expire:' . $expire . "\n";
        if ( true == $userbuf_enabled ) {
            $content_to_be_signed .= 'TLS.userbuf:' . $base64_userbuf . "\n";
        }
        return base64_encode( hash_hmac( 'sha256', $content_to_be_signed, $this->key, true ) );
    }

    /**
    * Generate signature.
    *
    * @param $identifier user account
    * @param int $expire Expiration time, in seconds, default 180 days
    * @param $userbuf base64 encoded userbuf
    * @param $userbuf_enabled Whether to enable userbuf
    * @return string signature string
    * @throws \Exception
    */
    private function __genSig( $identifier, $expire, $userbuf, $userbuf_enabled ) {
        $curr_time = time();
        $sig_array = Array(
            'TLS.ver' => '2.0',
            'TLS.identifier' => strval( $identifier ),
            'TLS.sdkappid' => intval( $this->sdkappid ),
            'TLS.expire' => intval( $expire ),
            'TLS.time' => intval( $curr_time )
        );

        $base64_userbuf = '';
        if ( true == $userbuf_enabled ) {
            $base64_userbuf = base64_encode( $userbuf );
            $sig_array['TLS.userbuf'] = strval( $base64_userbuf );
        }

        $sig_array['TLS.sig'] = $this->hmacsha256( $identifier, $curr_time, $expire, $base64_userbuf, $userbuf_enabled );
        if ( $sig_array['TLS.sig'] === false ) {
            throw new \Exception( 'base64_encode error' );
        }
        $json_str_sig = json_encode( $sig_array );
        if ( $json_str_sig === false ) {
            throw new \Exception( 'json_encode error' );
        }
        $compressed = gzcompress( $json_str_sig );
        if ( $compressed === false ) {
            throw new \Exception( 'gzcompress error' );
        }
        return $this->base64_url_encode( $compressed );
    }

    /**
    * Verify signature.
    *
    * @param string $sig Signature content
    * @param string $identifier Need to authenticate user name, utf-8 encoding
    * @param int $init_time Returned generation time, unix timestamp
    * @param int $expire_time Return the validity period, in seconds
    * @param string $userbuf returned user data
    * @param string $error_msg error message on failure
    * @return boolean Verify success
    * @throws \Exception
    */

    private function __verifySig( $sig, $identifier, &$init_time, &$expire_time, &$userbuf, &$error_msg ) {
        try {
            $error_msg = '';
            $compressed_sig = $this->base64_url_decode( $sig );
            $pre_level = error_reporting( E_ERROR );
            $uncompressed_sig = gzuncompress( $compressed_sig );
            error_reporting( $pre_level );
            if ( $uncompressed_sig === false ) {
                throw new \Exception( 'gzuncompress error' );
            }
            $sig_doc = json_decode( $uncompressed_sig );
            if ( $sig_doc == false ) {
                throw new \Exception( 'json_decode error' );
            }
            $sig_doc = ( array )$sig_doc;
            if ( $sig_doc['TLS.identifier'] !== $identifier ) {
                throw new \Exception( "identifier dosen't match" );
            }
            if ( $sig_doc['TLS.sdkappid'] != $this->sdkappid ) {
                throw new \Exception( "sdkappid dosen't match" );
            }
            $sig = $sig_doc['TLS.sig'];
            if ( $sig == false ) {
                throw new \Exception( 'sig field is missing' );
            }

            $init_time = $sig_doc['TLS.time'];
            $expire_time = $sig_doc['TLS.expire'];

            $curr_time = time();
            if ( $curr_time > $init_time+$expire_time ) {
                throw new \Exception( 'sig expired' );
            }

            $userbuf_enabled = false;
            $base64_userbuf = '';
            if ( isset( $sig_doc['TLS.userbuf'] ) ) {
                $base64_userbuf = $sig_doc['TLS.userbuf'];
                $userbuf = base64_decode( $base64_userbuf );
                $userbuf_enabled = true;
            }
            $sigCalculated = $this->hmacsha256( $identifier, $init_time, $expire_time, $base64_userbuf, $userbuf_enabled );

            if ( $sig != $sigCalculated ) {
                throw new \Exception( 'verify failed' );
            }

            return true;
        } catch ( \Exception $ex ) {
            $error_msg = $ex->getMessage();
            return false;
        }
    }

    /**
    * Verify signature with userbuf.
    *
    * @param string $sig Signature content
    * @param string $identifier Need to authenticate user name, utf-8 encoding
    * @param int $init_time Returned generation time, unix timestamp
    * @param int $expire_time Return the validity period, in seconds
    * @param string $error_msg error message on failure
    * @return boolean Verify success
    * @throws \Exception
    */
    public function verifySig( $sig, $identifier, &$init_time, &$expire_time, &$error_msg ) {
        $userbuf = '';
        return $this->__verifySig( $sig, $identifier, $init_time, $expire_time, $userbuf, $error_msg );
    }

    /**
    * Verify signature
    * @param string $sig Signature content
    * @param string $identifier Need to authenticate user name, utf-8 encoding
    * @param int $init_time Returned generation time, unix timestamp
    * @param int $expire_time Return the validity period, in seconds
    * @param string $userbuf returned user data
    * @param string $error_msg error message on failure
    * @return boolean Verify success
    * @throws \Exception
    */
    public function verifySigWithUserBuf( $sig, $identifier, &$init_time, &$expire_time, &$userbuf, &$error_msg ) {
        return $this->__verifySig( $sig, $identifier, $init_time, $expire_time, $userbuf, $error_msg );
    }
}
