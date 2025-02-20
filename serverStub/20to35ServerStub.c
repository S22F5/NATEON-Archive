// tested from 20_0006 to 35_0162
// after  35 unknown LSIN and NCPT response.
// before 20 unknown <login> response.
// CONF crash delete any *@nate.com folder in BIN/
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#define BUFFER_SIZE 8096
#define MAX_EVENTS 64
#define MAX_RESPONSES 10
#define SERVER_IP "192.168.56.1"
#define SERVER_PORT 5004

#define COLOR_RESET "\033[0m"
#define COLOR_INPUT "\033[0;32m"
#define COLOR_OUTPUT "\033[0;33m"

void reset_color(int signum);
void *tcp_server(void *arg);

int main() {
  pthread_t login_thread;
  signal(SIGINT, reset_color);

  pthread_create(&login_thread, NULL, tcp_server, NULL);
  pthread_join(login_thread, NULL);
  return 0;
}

void reset_color(int signum) {
    printf(COLOR_RESET);
    exit(signum);
}

void remove_newline_chars(const char *src, char *dest) {
  while (*src) {
    if (*src != '\r' && *src != '\n') {
      *dest++ = *src;
    }
    src++;
  }
  *dest = '\0';
}

void *handle_tcp_client(void *arg) {
  struct {
    int fd;
  } *thread_arg = arg;

  int sock = thread_arg->fd;
  free(arg);

  char buffer[BUFFER_SIZE];
  char response[BUFFER_SIZE];
  char cresponse[BUFFER_SIZE];
  char cmd[32];
  char *a;
  int trid;
  float pver;

  while (1) {
    ssize_t read_size = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (read_size <= 0)
      break;

    buffer[read_size] = '\0';
    sscanf(buffer, "%s %d", cmd, &trid);
    buffer[strcspn(buffer, "\r\n")] = '\0';
    printf(COLOR_INPUT "tcp: <- Received: %-30s\n" COLOR_RESET, buffer);

    if (strcmp(cmd, "PVER") == 0) {
      sscanf(buffer, "%s %d %f", cmd, &trid, &pver);
      printf("\n");
      snprintf(response, BUFFER_SIZE, "PVER %d %f\r\n", trid, pver);
    } else if (strcmp(cmd, "AUTH") == 0) {
      snprintf(response, BUFFER_SIZE, "AUTH %d MD5\r\n", trid);
    } else if (strcmp(cmd, "<login") == 0) {
      snprintf(response, BUFFER_SIZE, "<login type='query' to='PR'><id>1000000</id><ticket>169B84B70A9969F4452019A383CEF8D00326CA8741A1FBBC28C76A17E11603E6D5EF338D465F82E982FDB2EA0251BF0ED281EE17E3B086B6C825452D0850F1E3B408BCC1C38EAB8E</ticket><dispaddr>192.168.56.1</dispaddr></login>\r\n", trid);
    } else if (strcmp(cmd, "REQS") == 0) {
      snprintf(response, BUFFER_SIZE, "REQS %d dp1:1 %s 5004\r\n", trid, SERVER_IP);
    } else if (strcmp(cmd, "LSIN") == 0) {
      if (pver > 3.1) {
        /*if (pver >= 4.0) {
                snprintf(response, BUFFER_SIZE, "LSIN %d test01@nate.com 4A4F63EE431516A0A0F7A379C0B52E5DBA6261E761A4B4B327EA55AFE8473919B51058394636DBC59BD60F2D70D78CB1FF28D9E606FD7949CA167B6BDAB5C42104C7D30840A6C8D41D585BB1BBB98BC229445F861FB383863353E578DD8674927DD9B603CE5626662074D48981ADEEF97D7FC2CE7D427AF2B5BE6FA0C78776E07F70D06CE8E9EDA30ADB304D26FC4AA1BFD9A96F02D70B5D 54303057 1 %%00 %%00 N 10016018113 leechjun@nate.com g41axy@gmail.com N N KR %%00 %%00\r\n", trid);
        } else {*/
        snprintf(response, BUFFER_SIZE, "LSIN %d 1000000 username John%%20Smith 01234567890 JSmith@nate.com 169B84B70A9969F4452019A383CEF8D00326CA8741A1FBBC28C76A17E11603E6D5EF338D465F82E982FDB2EA0251BF0ED281EE17E3B086B6C825452D0850F1E3B408BCC1C38EAB8E %00 1 %00 %00 N 902126197 test01@lycos.co.kr %00 Y N\r\n", trid);
        //}
      } else {
        snprintf(response, BUFFER_SIZE, "LSIN %d 1000000 username John%%20Smith 01234567890 JSmith@nate.com 169B84B70A9969F4452019A383CEF8D00326CA8741A1FBBC28C76A17E11603E6D5EF338D465F82E982FDB2EA0251BF0ED281EE17E3B086B6C825452D0850F1E3B408BCC1C38EAB8E 17100022\r\n", trid);
      }
    } else if (strcmp(cmd, "CONF") == 0) {
      snprintf(response, BUFFER_SIZE, "CONF %d 2496 7932\r\n[ipml url]\r\n35U:3ctab_version=284\r\n35U:plugin_version=170\r\n37U:3ctab_version=284\r\n37U:keywordchat_version=12\r\n37U:plugin_version=173\r\n37U:servicechannel_version=24\r\n37UE:3ctab_version=284\r\n37UE:keywordchat_version=12\r\n37UE:plugin_version=167\r\n37UE:servicechannel_version=24\r\n37V:3ctab_version=284\r\n37V:keywordchat_version=12\r\n37V:plugin_version=172\r\n37V:servicechannel_version=24\r\n3ctab_ipml_url=http://nateon.nate.com/3ctab/3ctab.ipml\r\n3ctab_version=284\r\nC2:3ctab_version=284\r\nC2:cyworld_bridge_url=http://br.nate.com/index.php\r\nC2:nate_bridge_url=http://br.nate.com/index.php\r\nC2:nateon_logout_cgi_url=http://xso.nate.com/application/nateon_logout.jsp\r\nC2:plugin_version=100\r\nN3:3ctab_version=284\r\nN3:nateon_hottip_url=http://nateonweb.nate.com/help/guide_hottip_v3_main.html\r\nN3:notice_board_text=네이트온에서 중국어,일본어로 대화하세요\r\nN3:notice_board_url=http://nateonweb.nate.com/help/guide_download_main.html\r\nN3:plugin_version=83\r\nN3:sms_web_url=http://sms.nate.com/nateon30/nateonsms.jsp\r\nRSDaemonIP=203.226.253.81\r\nU:3ctab_version=284\r\nU:news_ticker_ipml=http://211.115.10.71/XMLFiles/nateon/unews.asp\r\nU:plugin_version=115\r\nU:todaytalk_ticker_url=http://bbs.nate.com/nateon/index_unicode.txt\r\nactionmemo_popular_url=http://avatar.nate.com/nateon/shop/EventLst.jsp\r\naddress_loading_timeout=60\r\naftersms_buddy_url=http://203.226.253.126/exipml35/recom_buddy_after_sms.jsp\r\nalert_ad_flag=Y\r\nalert_ipml_url=http://nateon.nate.com/notice/alert.ipml\r\navserver_addr1=203.226.253.76:5001\r\navserver_addr2=203.226.253.76:5011\r\nbgm_freeshop_url=http://aod.nate.com/bgm/nateon/music_list/free_music_popup.html\r\nbgm_list_url=http://aod.nate.com/bgm/nateon/asx/other_bgm.html\r\nbgm_load_flag=Y\r\nbgm_manage_url=http://aod.nate.com/bgm/nateon/mybgm/mybgm_ma.html\r\nbgm_mylisten_url=http://aod.nate.com/bgm/nateon/mybgm/mybuy_list_popup.html\r\nbgm_myzzimlist_url=http://aod.nate.com/bgm/nateon/zzim/mybgm_zzim_list.html\r\nbgm_shop_url=http://aod.nate.com/bgm/nateon/index_popup.html\r\nbgm_shopping_url=http://aod.nate.com/bgm/nateon/index.html\r\nbgm_zzimlist_url=http://aod.nate.com/bgm/nateon/zzim/other_zzim_list.html\r\nbuddy_error_fix_url=http://203.226.253.126/exipml35/buddy_error_fix.jsp\r\nbuddy_minihompy_url=http://nateonext.nate.com/cyworld/treasure/minihompy.jsp\r\nbuddy_search1_url=http://203.226.253.126/exipml35/search_buddy.jsp\r\nbuddy_search2_url=http://203.226.253.126/exipml35/search_fit.jsp\r\nbuddy_webadd_url=http://nateonweb.nate.com/bbs/skin/joinfriend/list.php?BBSID=3\r\nbuddyprofile_avatar_url=http://avatar.nate.com/jsps/shop/nateon-nme.jsp\r\nchange_password_url=http://member.nate.com/sccustomer/join/nate/modify/ChangePassword.jsp\r\ncyworld_findid_url=http://cyworld.nate.com/main2/email.asp\r\ncyworld_recom_buddy_disable=Y\r\ncyworld_recom_buddy_limit=0,20\r\ncyworld_regist_url=http://cyworld.nate.com/main2/register/register.asp\r\ndic_search_url=http://dic.nate.com/eng/DicEng01.asp?qw=nateon&query=\r\nerror_notice_url=http://nateon.nate.com/notice/error_notice.ipml\r\nevent_ipml_url=http://nateon.nate.com/notice/event20.ipml\r\neventfx_ipml_url=http://nateon.nate.com/notice/eventfx.ipml\r\nextmailurl=http://pcmail.nate.com/outmail/frame.php?noauth_id=\r\nflashcon_billing_url=/billing.php\r\nflashcon_cgi_url=http://flashcon.nate.com\r\nflashcon_file_url=http://flashcon.nate.com/upload\r\nflashcon_freecount_update_url=/update_freecount.php\r\nflashcon_help_url=/help/index.php\r\nflashcon_init_url=/init_flashcon.php\r\nget_invite_msg_url=http://203.226.253.126/exipml35/get_invite_msg.jsp\r\nget_profile_url=http://203.226.253.126/exipml35/get_profile.jsp\r\nget_timestamp_url=http://203.226.253.126/exipml35/timestamp.jsp\r\nhelp_url=http://nateon.nate.com/demo/index.html\r\nhotclip_size=600,501\r\nhotclip_url=http://hotclip.nate.com/index.php\r\nimageticker_interval=900000\r\nimageticker_ipml=http://cyad.nate.com/js.kti/nateon/nateon.nate.com@roc_btn_Bottom\r\nimcg_system_id=e2986839289860c00913264c983060c00913264c983060c0\r\nimcg_system_pwd=e2986839286cb060060d1b366cd8b060060d1b366cd8b060\r\ninvite_add_buddy_url=http://203.226.253.126/exipml20/recom_add_buddy.jsp\r\ninvite_cyworld_buddy_url=http://203.226.253.126/exipml35/invite_cyworld_buddy.jsp\r\ninvite_link_url=http://nateon.nate.com/invite/login.jsp\r\ninvite_sendmail_url=http://203.226.253.126/exipml35/add_buddy.jsp\r\nkbank_search_url=http://kbank.nate.com/qna/QaResultList.asp?Soption=2&Eoption=2&qw=nateon&Stext=\r\nlogin_fail_faq_url=http://nateonevent.nate.com/popup/20040430_network_err/naetworkErr_index.html\r\nmail_mybox_template_url=http://nateonevent.nate.com/Mail/MyBox.html\r\nmailbase_ipml=http://pcmail.nate.com/\r\nmailbase_ipml2=http://mi.nate.com/\r\nmailnotimgr_url=http://mailop.nate.com/mailnotimgr\r\nmailstart_dual_flag=Y\r\nmailwrite_invite_url=http://nateon.nate.com/Mail/mail_invite/mail_invite.html\r\nmemo_cnt_ipml=http://203.226.253.126/exipml35/memoCnt.jsp\r\nmemo_ipml=http://203.226.253.126/exipml35/memo.jsp\r\nmemo_login_link_list=http://mybgm.nate.com\r\nmemo_maxsender=50\r\nmim_ipml_base=http://203.226.253.126/mimpc35/\r\nmim_service_closed=0\r\nmim_use_image=Y\r\nminihompy_browser_size=932,538\r\nminihompy_cgi_baseurl=http://cyworld.nate.com/pims/nateon/\r\nminihompy_intro_url=http://cyworld.nate.com/main2/preview_minihp.asp\r\nminihompy_logincheck_flag=Y\r\nmsn_expose_flag=N\r\nmy_minihompy_url=http://nateonext.nate.com/cyworld/my_minihompy.jsp\r\nmyprofile_avatar_url=http://avatar.nate.com/jsps/shop/nateon-me.jsp\r\nnate_regist_url=http://member.nate.com/sccustomer/join/nate/index.jsp\r\nnate_url=http://www.nate.com\r\nnate_web_des_auth=http://xso.nate.com/application/cmlogin.jsp\r\nnateon_emoticon_baseurl=http://nateon.nate.com/emoticons/\r\nnateon_faq_url=http://nateonweb.nate.com/help/guide_faqsearch_list.html\r\nnateon_help_url=http://nateonweb.nate.com/help/guide_demo_pc_001.html\r\nnateon_hottip_url=http://nateonweb.nate.com/help/guide_hottip_v2_main.html\r\nnateon_ipml_url=http://nateon.nate.com/notice/nateon.ipml\r\nnateon_logout_cgi_url=http://xso.nate.com/logout.jsp\r\nnateon_mimhelp_url=http://mim.nate.com/web/new/\r\nnateon_search_text=검색할 단어를 입력하세요\r\nnego_idle=30\r\nnego_port=6004\r\nnego_retry=10\r\nnew_emoticon=N\r\nnew_flashcon=Y\r\nnews_search_url=http://newsearch.nate.com/result.asp?qw=nateon&query=\r\nnews_ticker_interval=3600000\r\nnews_ticker_ipml=http://211.115.10.71/XMLFiles/nateon/anews.asp\r\nnotice_board_text=네이트온에서 중국어,일본어로 대화하세요\r\nnotice_board_url=http://nateonweb.nate.com/help/guide_download_main.html\r\nnotice_ipml_url=http://nateon.nate.com/notice/notice20.ipml\r\np2p_maxcon=10\r\npimsmobile_buddy_url=http://203.226.253.126/exipml35/recom_buddy_pims_mobile.jsp\r\nplugin_url=http://nateon.nate.com/plugin/plugin.ipml\r\nplugin_version=71\r\npong_send_interval=40\r\npong_send_timeout=120\r\nrecom_buddy_limit=-1,-1\r\nrecom_cyworld_buddy_url=http://203.226.253.126/exipml35/recom_buddy_cyworld.jsp\r\nregister_url=http://member.nate.com/sccustomer/join/nate/index.jsp\r\nremove_mobilebox=N\r\nsearch_device_url=http://203.226.253.126/exipml35/search_device.jsp\r\nslidewnd_version=33\r\nsms_msgbox_colorrecv_url=http://vmms.nate.com:8282/cmail/receive/receive_nateon.jsp\r\nsms_msgbox_colorsend_url=http://vmms.nate.com:8282/cmail/send/send_nateon.jsp\r\nsms_msgbox_groupresv_url=http://sms.nate.com/group/nateon_letter_04.jsp\r\nsms_msgbox_groupsend_url=http://sms.nate.com/group/nateon_letter_03.jsp\r\nsms_msgbox_url=http://sms.nate.com/servlets/NateonMessageServlet\r\nsms_web_url=http://sms.nate.com/nateon/nateonsms.jsp\r\nsmspage=http://sms.nate.com/nateon_message/NateOn_MsgBox.jsp\r\nspammailtime_ipml=http://pcmail.nate.com/NateOnGetTime.php\r\nticket_update_interval=80\r\ntmsgbox_url=http://nateonext.nate.com/tmsgbox/TMsgBoxMain.html\r\ntoday_update_time=14:00\r\ntodaytalk_ticker_url=http://bbs.nate.com/nateon/index.txt\r\ntoolbar_reset_serial=4\r\ntotal_search_url=http://search.nate.com/search/srch_allindex.asp?searchfield=total&qw=nateon&query=\r\nupdate_ticket_url=http://203.226.253.126/exipml20/update_ticket.jsp\r\nwebmemo_version=3\r\n\r\n", trid);
    } else if (strcmp(cmd, "GLST") == 0) {
      snprintf(response, BUFFER_SIZE, "GLST %d 0 0\r\n", trid);
    } else if (strcmp(cmd, "NCPT") == 0) {
      snprintf(response, BUFFER_SIZE, "NCPT %d PWD BASE64 7 cGFzcw==\r\n", trid);
    } else if (strcmp(cmd, "LIST") == 0) {
      snprintf(response, BUFFER_SIZE, "LIST %d 0 000 0000 JSmith@nate.com 1000000 username username %00  %00 1998 0 1\r\n", trid);
    } else if (strcmp(cmd, "ADDB") == 0) {
      snprintf(response, BUFFER_SIZE, "ADDB %d 1000010\r\n\r\n", trid);
    } else if (strcmp(cmd, "PING") == 0) {
      snprintf(response, BUFFER_SIZE, "PING %d\r\n", trid);
    } else if (strcmp(cmd, "PONG") == 0) {
      snprintf(response, BUFFER_SIZE, "PONG %d\r\n", trid);
    } else {
      snprintf(response, BUFFER_SIZE, "UKNW %d\r\n", trid);
      // snprintf(response, BUFFER_SIZE, "%s %d ECHOED\r\n",cmd , trid);
    }

    send(sock, response, strlen(response), 0);

    remove_newline_chars(response, cresponse);
    printf(COLOR_OUTPUT "tcp: -> Sent: %-30s\n" COLOR_RESET, cresponse);
  }

  close(sock);
  return NULL;
}

void *tcp_server(void *arg) {

  int server_fd;
  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = INADDR_ANY,
      .sin_port = htons(SERVER_PORT)};

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket failed");
    return NULL;
  }

  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(int){1}, sizeof(int));
  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind failed");
    close(server_fd);
    return NULL;
  }
  listen(server_fd, 10);

  printf("add these lines to your hosts file: \n");
  printf("%s    impp.nate.com\n", SERVER_IP);
  printf("%s    dpl.nate.com\n", SERVER_IP);
  printf("%s    nateon.nate.com\n", SERVER_IP);
  printf("%s    prs.nate.com\n\n", SERVER_IP);

  printf("Server listening on %s:%d\n", SERVER_IP, SERVER_PORT);

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0)
      continue;

    struct {
      int fd;
    } *thread_arg = malloc(sizeof(*thread_arg));
    thread_arg->fd = client_fd;

    pthread_t thread;
    pthread_create(&thread, NULL, handle_tcp_client, thread_arg);
    pthread_detach(thread);
  }
  close(server_fd);
  return NULL;
}