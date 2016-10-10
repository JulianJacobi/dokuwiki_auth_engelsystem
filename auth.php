<?php

/**
 * Created by PhpStorm.
 * User: jayjay
 * Date: 09.10.16
 * Time: 01:02
 */
class auth_plugin_authengelsystem extends DokuWiki_Auth_Plugin
{

    /** @var PDO */
    private $db;

    public function __construct()
    {
        try {
            $this->db = new PDO(
                'mysql:host='.$this->getConf('host').';dbname='.$this->getConf('database'),
                $this->getConf('username'), $this->getConf('password')
            );
            $this->success = true;
        } catch (PDOException $e) {
            print('Auth Engelsystem: Failed Database Connection:'. $e->getMessage());
            $this->success = false;
        }

        $this->cando['addUser']     = false;    // can Users be created?
        $this->cando['delUser']     = false;    // can Users be deleted?
        $this->cando['modLogin']    = false;    // can login names be changed?
        $this->cando['modPass']     = false;    // can passwords be changed?
        $this->cando['modName']     = false;    // can real names be changed?
        $this->cando['modMail']     = false;    // can emails be changed?
        $this->cando['modGroups']   = false;    // can groups be changed?
        $this->cando['getUsers']    = false;    // can a (filtered) list of users be retrieved?
        $this->cando['getUserCount']= false;    // can the number of users be retrieved?
        $this->cando['getGroups']   = false;    // can a list of available groups be retrieved?
        $this->cando['external']    = false;     // does the module do external auth checking?
        $this->cando['logout']      = true;     // can the user logout again?

    }

    public function checkPass($user, $pass)
    {
        $result = $this->db->query("SELECT User.UID as id, User.Nick as username, User.Passwort as password FROM User WHERE Nick = '".$user."'");

        $rows = $result->fetchAll();

        $dbPass = $rows[0]['password'];

        return $this->verify_password($pass, $dbPass);

    }

    public function getUserData($user, $requireGroups = true)
    {
        $result = $this->db->query("SELECT UID as id, CONCAT(User.Vorname, ' ', User.Name) as name, email as mail FROM User WHERE User.Nick = '".$user."'");
        $return = $result->fetchAll()[0];

        if($requireGroups) {
            $result2 = $this->db->query("SELECT Groups.Name as name FROM UserGroups INNER JOIN Groups ON UserGroups.group_id = Groups.UID WHERE UserGroups.uid = '".$return['id']."'");
            $rows = $result2->fetchAll();
            $groups = array();
            foreach ($rows as $row) {
                $groups[] = str_replace(' ', '-', $row['name']);
            }
            $return['grps'] = $groups;
        }
        //var_dump($return);
        return $return;
    }

    /**
     * verify a password given a precomputed salt.
     * if $uid is given and $salt is an old-style salt (plain md5), we convert it automatically
     */
    private function verify_password($password, $salt) {
        $correct = false;
        if (substr($salt, 0, 1) == '$') { // new-style crypt()
            $correct = crypt($password, $salt) == $salt;
        } elseif (substr($salt, 0, 7) == '{crypt}') { // old-style crypt() with DES and static salt - not used anymore
            $correct = crypt($password, '77') == $salt;
        } elseif (strlen($salt) == 32) { // old-style md5 without salt - not used anymore
            $correct = md5($password) == $salt;
        }

        return $correct;
    }

}