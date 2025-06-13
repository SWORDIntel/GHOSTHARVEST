import asyncio
import os
import logging
import unittest
from unittest.mock import patch, AsyncMock, MagicMock, call # Added call

# Modules to be tested or mocked
from src import ip_rotator
# Need to ensure that when ip_rotator imports config and utils, they are patchable
# or that we patch them at the level of the ip_rotator module.


class TestIPRotator(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Reset global states in ip_rotator module before each test
        ip_rotator.wireguard_interfaces = []
        ip_rotator.current_interface = None
        # Suppress logging output during tests unless specifically testing for it
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        # Re-enable logging
        logging.disable(logging.NOTSET)

    # --- Tests for init_wireguard_interfaces ---

    @patch('src.ip_rotator.os.listdir')
    @patch('src.ip_rotator.config') # Mock the config module used by ip_rotator
    async def test_init_finds_conf_files(self, mock_config, mock_listdir):
        mock_config.WG_CONFIG_DIR = "/dummy/wg/path"
        mock_listdir.return_value = ['wg0.conf', 'wg1.conf', 'notaconf.txt', 'wg2.CONF']

        await ip_rotator.init_wireguard_interfaces()

        self.assertCountEqual(ip_rotator.wireguard_interfaces, ['wg0', 'wg1', 'wg2'])
        mock_listdir.assert_called_once_with("/dummy/wg/path")

    @patch('src.ip_rotator.os.listdir')
    @patch('src.ip_rotator.config')
    async def test_init_no_conf_files(self, mock_config, mock_listdir):
        mock_config.WG_CONFIG_DIR = "/dummy/wg/path"
        mock_listdir.return_value = ['nonconf.txt', 'another.file']

        await ip_rotator.init_wireguard_interfaces()

        self.assertEqual(ip_rotator.wireguard_interfaces, [])

    @patch('src.ip_rotator.os.listdir')
    @patch('src.ip_rotator.config')
    @patch('src.ip_rotator.logging') # To check log messages
    async def test_init_config_dir_not_found(self, mock_logging, mock_config, mock_listdir):
        mock_config.WG_CONFIG_DIR = "/nonexistent/path"
        mock_listdir.side_effect = FileNotFoundError("Directory not found")

        await ip_rotator.init_wireguard_interfaces()

        self.assertEqual(ip_rotator.wireguard_interfaces, [])
        mock_logging.error.assert_any_call(f"WireGuard configuration directory not found: {mock_config.WG_CONFIG_DIR}")

    # --- Tests for rotate_wireguard_ip ---

    @patch('src.ip_rotator.asyncio.create_subprocess_shell', new_callable=AsyncMock)
    @patch('src.ip_rotator.utils.get_current_public_ip', new_callable=AsyncMock)
    @patch('src.ip_rotator.asyncio.sleep', new_callable=AsyncMock)
    @patch('src.ip_rotator.config') # Mock config for any potential direct use (though not in current ip_rotator)
    @patch('src.ip_rotator.logging')
    async def test_rotate_successful_first_rotation(self, mock_logging, mock_config, mock_sleep, mock_get_ip, mock_subprocess_shell):
        ip_rotator.wireguard_interfaces = ['wg0', 'wg1']
        ip_rotator.current_interface = None

        # Mock subprocess behavior for 'wg-quick up'
        mock_process_up = AsyncMock()
        mock_process_up.communicate = AsyncMock(return_value=(b"output", b""))
        mock_process_up.returncode = 0
        mock_subprocess_shell.return_value = mock_process_up

        mock_get_ip.return_value = "1.2.3.4"

        result = await ip_rotator.rotate_wireguard_ip()

        self.assertTrue(result)
        mock_subprocess_shell.assert_called_once() # Only 'up' should be called
        self.assertTrue("wg-quick up" in mock_subprocess_shell.call_args[0][0])
        self.assertIn(ip_rotator.current_interface, ['wg0', 'wg1'])
        mock_sleep.assert_called_once_with(5)
        mock_get_ip.assert_called_once()
        mock_logging.info.assert_any_call(f"Successfully rotated IP. New public IP: 1.2.3.4 via {ip_rotator.current_interface}")


    @patch('src.ip_rotator.asyncio.create_subprocess_shell', new_callable=AsyncMock)
    @patch('src.ip_rotator.utils.get_current_public_ip', new_callable=AsyncMock)
    @patch('src.ip_rotator.asyncio.sleep', new_callable=AsyncMock)
    @patch('src.ip_rotator.logging')
    async def test_rotate_successful_subsequent_rotation(self, mock_logging, mock_sleep, mock_get_ip, mock_subprocess_shell):
        ip_rotator.wireguard_interfaces = ['wg0', 'wg1']
        ip_rotator.current_interface = 'wg0'

        # Mock subprocess for 'down' then 'up'
        mock_process_down = AsyncMock()
        mock_process_down.communicate = AsyncMock(return_value=(b"", b""))
        mock_process_down.returncode = 0

        mock_process_up = AsyncMock()
        mock_process_up.communicate = AsyncMock(return_value=(b"output", b""))
        mock_process_up.returncode = 0

        mock_subprocess_shell.side_effect = [mock_process_down, mock_process_up]
        mock_get_ip.return_value = "1.2.3.5"

        result = await ip_rotator.rotate_wireguard_ip()

        self.assertTrue(result)
        self.assertEqual(mock_subprocess_shell.call_count, 2)
        mock_subprocess_shell.assert_any_call("sudo wg-quick down wg0", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        # The new interface should be wg1, as wg0 was current
        self.assertTrue("wg-quick up wg1" in mock_subprocess_shell.call_args_list[1][0][0])
        self.assertEqual(ip_rotator.current_interface, 'wg1')
        mock_get_ip.assert_called_once()
        mock_logging.info.assert_any_call("Successfully brought down wg0.")
        mock_logging.info.assert_any_call(f"Successfully rotated IP. New public IP: 1.2.3.5 via wg1")


    @patch('src.ip_rotator.asyncio.create_subprocess_shell', new_callable=AsyncMock)
    @patch('src.ip_rotator.utils.get_current_public_ip', new_callable=AsyncMock) # Should not be called if 'up' fails
    @patch('src.ip_rotator.logging')
    async def test_rotate_wg_quick_up_fails(self, mock_logging, mock_get_ip, mock_subprocess_shell):
        ip_rotator.wireguard_interfaces = ['wg0']
        ip_rotator.current_interface = None # Start with no active interface

        mock_process_up_fail = AsyncMock()
        mock_process_up_fail.communicate = AsyncMock(return_value=(b"", b"Error bringing up interface"))
        mock_process_up_fail.returncode = 1
        mock_subprocess_shell.return_value = mock_process_up_fail

        result = await ip_rotator.rotate_wireguard_ip()

        self.assertFalse(result)
        mock_subprocess_shell.assert_called_once_with("sudo wg-quick up wg0", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        mock_logging.error.assert_any_call("Failed to bring up wg0. Error: Error bringing up interface")
        self.assertIsNone(ip_rotator.current_interface) # Should be reset or remain None
        mock_get_ip.assert_not_called()


    @patch('src.ip_rotator.asyncio.create_subprocess_shell', new_callable=AsyncMock)
    @patch('src.ip_rotator.utils.get_current_public_ip', new_callable=AsyncMock)
    @patch('src.ip_rotator.asyncio.sleep', new_callable=AsyncMock) # For the restore logic
    @patch('src.ip_rotator.logging')
    async def test_rotate_wg_quick_up_fails_attempts_restore(self, mock_logging, mock_sleep, mock_get_ip, mock_subprocess_shell):
        ip_rotator.wireguard_interfaces = ['wg0', 'wg1']
        original_interface = 'wg0'
        ip_rotator.current_interface = original_interface

        new_interface_candidate = 'wg1' # Assume random choice picks wg1

        mock_process_down_wg0 = AsyncMock(); mock_process_down_wg0.returncode = 0; mock_process_down_wg0.communicate = AsyncMock(return_value=(b'',b''))
        mock_process_up_wg1_fail = AsyncMock(); mock_process_up_wg1_fail.returncode = 1; mock_process_up_wg1_fail.communicate = AsyncMock(return_value=(b'',b'fail up wg1'))
        mock_process_up_wg0_restore_success = AsyncMock(); mock_process_up_wg0_restore_success.returncode = 0; mock_process_up_wg0_restore_success.communicate = AsyncMock(return_value=(b'',b''))

        # Order of calls: down wg0, up wg1 (fails), up wg0 (restore)
        mock_subprocess_shell.side_effect = [
            mock_process_down_wg0,
            mock_process_up_wg1_fail,
            mock_process_up_wg0_restore_success
        ]

        # This mock is for the get_current_public_ip call if the restore is successful
        # However, the main function returns False if the *new* IP verification fails.
        # The problem statement says "Return False if ... error occurred".
        # If restore happens, it should still return False because the goal was to get a *new* IP.
        # Let's assume get_current_public_ip is NOT called after a failed 'up' attempt, even if restore works.
        # The current code in ip_rotator.py would call it if restore works. Let's test that path.
        mock_get_ip.return_value = "1.2.3.4" # IP of restored wg0

        # Patch random.choice to control which new interface is selected
        with patch('src.ip_rotator.random.choice', return_value=new_interface_candidate) as mock_random_choice:
            result = await ip_rotator.rotate_wireguard_ip()

        self.assertFalse(result) # Rotation to a NEW interface failed

        self.assertEqual(mock_subprocess_shell.call_count, 3)
        calls = [
            call(f"sudo wg-quick down {original_interface}", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE),
            call(f"sudo wg-quick up {new_interface_candidate}", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE),
            call(f"sudo wg-quick up {original_interface}", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE) # Restore
        ]
        mock_subprocess_shell.assert_has_calls(calls, any_order=False)

        mock_logging.error.assert_any_call(f"Failed to bring up {new_interface_candidate}. Error: fail up wg1")
        # The current code in ip_rotator.py updates current_interface to the restored one
        # but then the function returns False. And it doesn't re-verify IP for the restored.
        # The problem description implies get_current_public_ip is for the NEW ip.
        # If restore logic is complex and involves IP check, test would need more.
        # Based on current ip_rotator.py code, current_interface would be original_interface if restore works.
        self.assertEqual(ip_rotator.current_interface, original_interface)
        mock_get_ip.assert_not_called() # IP verification only for the new interface attempt.


    @patch('src.ip_rotator.asyncio.create_subprocess_shell', new_callable=AsyncMock)
    @patch('src.ip_rotator.utils.get_current_public_ip', new_callable=AsyncMock)
    @patch('src.ip_rotator.asyncio.sleep', new_callable=AsyncMock)
    @patch('src.ip_rotator.logging')
    async def test_rotate_wg_quick_down_fails_proceeds_to_up_success(self, mock_logging, mock_sleep, mock_get_ip, mock_subprocess_shell):
        ip_rotator.wireguard_interfaces = ['wg0', 'wg1']
        ip_rotator.current_interface = 'wg0'

        mock_process_down_fail = AsyncMock(); mock_process_down_fail.returncode = 1; mock_process_down_fail.communicate = AsyncMock(return_value=(b"", b"fail down wg0"))
        mock_process_up_success = AsyncMock(); mock_process_up_success.returncode = 0; mock_process_up_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_subprocess_shell.side_effect = [mock_process_down_fail, mock_process_up_success]
        mock_get_ip.return_value = "1.2.3.5" # New IP for wg1

        # Patch random.choice to ensure 'wg1' is chosen
        with patch('src.ip_rotator.random.choice', return_value='wg1'):
            result = await ip_rotator.rotate_wireguard_ip()

        self.assertTrue(result)
        self.assertEqual(mock_subprocess_shell.call_count, 2)
        mock_subprocess_shell.assert_any_call("sudo wg-quick down wg0", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        mock_subprocess_shell.assert_any_call("sudo wg-quick up wg1", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        mock_logging.error.assert_any_call("Failed to bring down wg0. Error: fail down wg0")
        self.assertEqual(ip_rotator.current_interface, 'wg1')
        mock_get_ip.assert_called_once()


    @patch('src.ip_rotator.asyncio.create_subprocess_shell', new_callable=AsyncMock)
    @patch('src.ip_rotator.logging')
    async def test_rotate_no_interfaces_available(self, mock_logging, mock_subprocess_shell):
        ip_rotator.wireguard_interfaces = [] # No interfaces

        result = await ip_rotator.rotate_wireguard_ip()

        self.assertFalse(result)
        mock_subprocess_shell.assert_not_called()
        mock_logging.error.assert_any_call("No WireGuard interfaces available to rotate.")

    @patch('src.ip_rotator.asyncio.create_subprocess_shell', new_callable=AsyncMock)
    @patch('src.ip_rotator.utils.get_current_public_ip', new_callable=AsyncMock)
    @patch('src.ip_rotator.asyncio.sleep', new_callable=AsyncMock)
    @patch('src.ip_rotator.logging')
    async def test_rotate_only_one_interface(self, mock_logging, mock_sleep, mock_get_ip, mock_subprocess_shell):
        ip_rotator.wireguard_interfaces = ['wg0']
        ip_rotator.current_interface = 'wg0' # Start with it active

        mock_process_down_wg0 = AsyncMock(); mock_process_down_wg0.returncode = 0; mock_process_down_wg0.communicate = AsyncMock(return_value=(b'',b''))
        mock_process_up_wg0 = AsyncMock(); mock_process_up_wg0.returncode = 0; mock_process_up_wg0.communicate = AsyncMock(return_value=(b'',b''))

        mock_subprocess_shell.side_effect = [mock_process_down_wg0, mock_process_up_wg0]
        mock_get_ip.return_value = "1.2.3.4"

        result = await ip_rotator.rotate_wireguard_ip()

        self.assertTrue(result)
        self.assertEqual(mock_subprocess_shell.call_count, 2)
        calls = [
            call("sudo wg-quick down wg0", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE),
            call("sudo wg-quick up wg0", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        ]
        mock_subprocess_shell.assert_has_calls(calls, any_order=False)
        self.assertEqual(ip_rotator.current_interface, 'wg0')
        mock_get_ip.assert_called_once()
        mock_logging.info.assert_any_call(f"Successfully rotated IP. New public IP: 1.2.3.4 via wg0")

if __name__ == '__main__':
    unittest.main()
