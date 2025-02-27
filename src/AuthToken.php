<?php

/**
 * This file is part of the ProxmoxVE PHP API wrapper library (unofficial).
 *
 * @copyright 2014 César Muñoz <zzantares@gmail.com>
 * @license http://opensource.org/licenses/MIT The MIT License.
 */

namespace ProxmoxVE;

/**
 * AuthToken class. Handles all data used when talking to a promxox server like
 * the CSRF token, login ticket, etc.
 *
 * @author César Muñoz <zzantares@gmail.com>
 */
class AuthToken
{
    /**
     * UNIX time when this object was created. Used for check ticket validity.
     *
     * @var integer
     */
    private $timestamp;


    /**
     * Random text used by Proxmox as CSRF prevention token in some requests.
     *
     * @see http://pve.proxmox.com/wiki/Proxmox_VE_API#Authentification
     * @var string
     */
    private $CSRFPreventionToken;


    /**
     * Random text used to identify a valid session at Proxmox.
     *
     * @see http://pve.proxmox.com/wiki/Proxmox_VE_API#Authentification
     * @var string
     */
    private $ticket;


    /**
     * Username that owns this Proxmox session ticket.
     *
     * @see http://pve.proxmox.com/wiki/Proxmox_VE_API#Authentification
     * @var string
     */
    private $username;


    /**
     * Constructor.
     *
     * @param string $username   The username that owns the login ticket.
     * @param string $ticket     The ticket representing a valid session given
     *                           by Proxmox at login time.
     * @param string $csrf       The CSRF prevention token given by Proxmox at
     *                           login time.
     */
    public function __construct($csrf, $ticket, $username)
    {
        $this->timestamp = time();
        $this->CSRFPreventionToken = $csrf;
        $this->ticket = $ticket;
        $this->username = $username;
    }


    /**
     * Returns the CSRF prevention token generated by Proxmox at login time.
     *
     * @return string The CSRF prevention token.
     */
    public function getCsrf()
    {
        return $this->CSRFPreventionToken;
    }


    /**
     * Returns the login ticket given by Proxmox at login time.
     *
     * @return string The ticket representing a valid Proxmox session.
     *
     */
    public function getTicket()
    {
        return $this->ticket;
    }


    /**
     * Returns the username of the form 'user@realm' associated with this
     * AuthToken.
     *
     * @return string Username found in this AuthToken.
     */
    public function getUsername()
    {
        return $this->username;
    }


    /**
     * Returns the timestamp when this AuthToken was created.
     *
     * @return integer The UNIX timestamp generated at the moment of AuthToken
     *                 creation.
     */
    public function getTimestamp()
    {
        return $this->timestamp;
    }


    /**
     * Tells if the ticket in this AuthToken is still valid for requesting the
     * Proxmox server. A ticket is valid only for 2 hours.
     *
     * @return boolean Will be true if it is still valid, false otherwise.
     */
    public function isValid()
    {
        return $this->timestamp + 7000 >= time();
    }
}
