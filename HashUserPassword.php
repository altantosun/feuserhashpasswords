<?php

declare(strict_types=1);

namespace AltanTosun\Wizard\Install\Updates;

use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Install\Updates\AbstractUpdate;
use TYPO3\CMS\Saltedpasswords\Salt\BlowfishSalt;
use TYPO3\CMS\Saltedpasswords\Salt\Md5Salt;
use TYPO3\CMS\Saltedpasswords\Salt\Pbkdf2Salt;
use TYPO3\CMS\Saltedpasswords\Salt\PhpassSalt;

class HashUserPassword extends AbstractUpdate
{
    protected $userTable = 'fe_users';
    protected $passwordColumn = 'password';

    /**
     * @var string
     */
    protected $title = 'hashUserPassword';

    /**
     * @param string $description
     * @return bool
     */
    public function checkForUpdate(&$description): bool
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)->getQueryBuilderForTable($this->userTable);
        $count = $queryBuilder
            ->select($this->passwordColumn)
            ->from($this->userTable)
            ->where(
                $queryBuilder->expr()->notLike($this->passwordColumn, $queryBuilder->createNamedParameter('$argon2%')),
                $queryBuilder->expr()->notLike($this->passwordColumn, $queryBuilder->createNamedParameter('$pbkdf2%')),
                $queryBuilder->expr()->notLike($this->passwordColumn, $queryBuilder->createNamedParameter('$P$C%')),
                $queryBuilder->expr()->notLike($this->passwordColumn, $queryBuilder->createNamedParameter('$1$%')),
                $queryBuilder->expr()->notLike($this->passwordColumn, $queryBuilder->createNamedParameter(''))
            )
            ->execute()
            ->rowCount();

        return $count > 0;
    }

    /**
     * @param array $dbQueries
     * @param string $customMessage
     * @return bool
     * @throws \Exception
     */
    public function performUpdate(array &$dbQueries, &$customMessage): bool
    {
        /** @var ConnectionPool $connectionPool */
        $connectionPool = GeneralUtility::makeInstance(ConnectionPool::class);
        $connection = $connectionPool->getQueryBuilderForTable($this->userTable);

        $pbkdf2PasswordProcessor = GeneralUtility::makeInstance(Pbkdf2Salt::class);

        // get disabled and hidden records as well
        $connection
            ->getRestrictions()
            ->removeAll();

        $statement = $connection
            ->select('uid', $this->passwordColumn)
            ->from($this->userTable)
            ->where(
                $connection->expr()->notLike($this->passwordColumn, $connection->createNamedParameter('$argon2%')),
                $connection->expr()->notLike($this->passwordColumn, $connection->createNamedParameter('$pbkdf2%')),
                $connection->expr()->notLike($this->passwordColumn, $connection->createNamedParameter('$P$C%')),
                $connection->expr()->notLike($this->passwordColumn, $connection->createNamedParameter('$1$%')),
                $connection->expr()->notLike($this->passwordColumn, $connection->createNamedParameter('')),
            )
            ->execute();

        while ($row = $statement->fetch()) {
            if ($row['password'] === null || $row['password'] === '') {
                continue;
            }

            $isPasswordHashed = $this->_isPasswordHashed($row['password']);

            if ($isPasswordHashed === true) {
                continue;
            }

            /**
                $isHashUpdateNeeded = $this->_isHashUpdateNeeded($row['password']);
               if ($isHashUpdateNeeded === false) {
                    continue;
               }
             // Does not seem to work for the "13" char passwords
             **/
            $hashedPassword = $pbkdf2PasswordProcessor->getHashedPassword($row['password']);

            $connection
                ->update($this->userTable)
                ->set($this->passwordColumn, $hashedPassword)
                ->where($connection->expr()->eq('uid', $connection->createNamedParameter($row['uid'])))
                ->execute();

            //UserFileUtility::writeToDebugFile('UID: ' . $row['uid'], $row['password'], $hashedPassword);
        }

        return true;
    }

    /**
     * @param string $userPassword
     * @return bool
     */
    protected function _isPasswordHashed(string $userPassword): bool
    {
        $md5PasswordProcessor = GeneralUtility::makeInstance(Md5Salt::class);
        $pbkdf2PasswordProcessor = GeneralUtility::makeInstance(Pbkdf2Salt::class);
        $blowfishSaltPasswordProcessor = GeneralUtility::makeInstance(BlowfishSalt::class);
        $phpassSaltSaltPasswordProcessor = GeneralUtility::makeInstance(PhpassSalt::class);

        $md5 = $md5PasswordProcessor->isValidSaltedPW($userPassword);
        $pbkdf2 = $pbkdf2PasswordProcessor->isValidSaltedPW($userPassword);
        $blowfish = $blowfishSaltPasswordProcessor->isValidSaltedPW($userPassword);
        $phpassSalt = $phpassSaltSaltPasswordProcessor->isValidSaltedPW($userPassword);

        return $md5 === true || $pbkdf2 === true || $blowfish === true || $phpassSalt === true;
    }

    protected function _isHashUpdateNeeded(string $userPassword): bool
    {
        $md5PasswordProcessor = GeneralUtility::makeInstance(Md5Salt::class);
        $pbkdf2PasswordProcessor = GeneralUtility::makeInstance(Pbkdf2Salt::class);
        $blowfishSaltPasswordProcessor = GeneralUtility::makeInstance(BlowfishSalt::class);
        $phpassSaltSaltPasswordProcessor = GeneralUtility::makeInstance(PhpassSalt::class);

        $md5 = $md5PasswordProcessor->isHashUpdateNeeded($userPassword);
        $pbkdf2 = $pbkdf2PasswordProcessor->isHashUpdateNeeded($userPassword);
        $blowfish = $blowfishSaltPasswordProcessor->isHashUpdateNeeded($userPassword);
        $phpassSalt = $phpassSaltSaltPasswordProcessor->isHashUpdateNeeded($userPassword);

        return $md5 === true && $pbkdf2 === true && $blowfish === true && $phpassSalt === true;
    }
}
