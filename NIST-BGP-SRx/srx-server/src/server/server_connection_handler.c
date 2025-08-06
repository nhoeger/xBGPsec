/**
 * This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of
 * their official duties. Pursuant to title 17 Section 105 of the United
 * States Code this software is not subject to copyright protection and
 * is in the public domain.
 *
 * NIST assumes no responsibility whatsoever for its use by other parties,
 * and makes no guarantees, expressed or implied, about its quality,
 * reliability, or any other characteristic.
 *
 * We would appreciate acknowledgment if the software is used.
 *
 * NIST ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE.
 *
 *
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required
 * by this software.
 *
 * @version 0.6.1.2
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.6.1.2  - 2021/11/15 - kyehwanl
 *            * Exchange the conditions to determine between sibling and lateral 
 *              peer.
 * 0.6.1.0  - 2021/08/27 - kyehwanl
 *            * Added logging informations
 * 0.6.0.0  - 2021/04/06 - oborchert
 *            * Modified access to asType and asRelType to common header.
 *          - 2021/02/26 - kyehwanl
 *            * Added ASPA processing
 * 0.5.0.1  - 2016/08/29 - oborchert
 *            * Fixed some compiler warnings.
 * 0.4.0.1  - 2016/07/02 - oborchert
 *            * Fixed wrongful conversion of a nework encoded word into a host
 *              encoded int. Changed from ntol to ntohs.
 * 0.3.0.10 - 2015/11/10 - oborchert
 *            * Fixed assignment bug in stopSCHReceiverQueue
 *            * Added return value (NULL) to schReceiverQueueThreadLoop
 * 0.3.0    - 2013/01/28 - oborchert
 *            * Finished mapping configuration.
 *          - 2013/01/22 - oborchert
 *            * Added internal receiver queue. (can be configured!)
 *          - 2013/01/05 - oborchert
 *            * Renamed ProxyClientMap into ProxyClientMaping
 *            * Added documentation to C file
 *          - 2013/01/04 - oborchert
 *            * Added isShutdown parameter to structure
 *          - 2012/12/31 - oborchert
 *            * Added Version control
 *            * Bug fix in prefix preparation for storing in update cache
 *          - 2012/12/17 - oborchert
 *            * Message flow partially rewritten.
 * 0.2.0    - 2011/11/01 - oborchert
 *            * Rewritten.
 * 0.0.0    - 2010/04/15 - pgleichm
 *            * Code Created
 * -----------------------------------------------------------------------------
 *
 */


 #include <stdio.h>
 #include <stdint.h>
 #include <openssl/evp.h>
 #include <openssl/ec.h>
 #include <openssl/ecdsa.h>
 #include <openssl/sha.h>
 #include <openssl/obj_mac.h>
 #include <openssl/pem.h>
 #include <openssl/err.h>
 #include <string.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include "util/log.h"
 #include "server/server_connection_handler.h"
 #include "server/srx_packet_sender.h"
 #include "server/aspath_cache.h"
 #include "shared/srx_identifier.h"
 #include "server/ski_cache.h"
 #include "shared/srx_packets.h"
 #include "shared/srx_defs.h"
#define HDR  "([0x%08X] SrvConnHdlr): "

////////////////////////////////////////////////////////////////////////////////
// The connection Handlers receiver queue.
////////////////////////////////////////////////////////////////////////////////

/** The element of the receiver queue */
typedef struct {
  ServerSocket* svrSock;
  ServerClient* client;
  uint8_t* pdu;
  uint32_t size;
  bool     consumed;
  void* next;
} SCH_ReceiverQueueElement;

/** the receiver queue itself */
typedef struct {
  // The head element, the next one to take
  SCH_ReceiverQueueElement* head;
  // The tail element, the last one added
  SCH_ReceiverQueueElement* tail;
  // the size of the queue
  int         size;
  // the queue handler itself
  pthread_t   handler;
  // indicates if the queue is running.
  bool        running;
  // Mutex and Condition for thread handling
  Mutex       mutex;
  Cond        condition;

  ServerConnectionHandler* svrConnHandler;
} SCH_ReceiverQueue;

// wait until notify or 1 s timeout - this is just to allow a wakeup
#define SCH_RECEIVE_QUEUE_WAIT_MS 1000

// Forward declaration
SCH_ReceiverQueueElement* fetchSCHReceiverPacket(SCH_ReceiverQueue* queue);
void stopSCHReceiverQueue(SCH_ReceiverQueue* queue);
void _handlePacket(ServerSocket* svrSock, ServerClient* client,
                   void* packet, PacketLength length, void* srvConHandler);

                   
/**
 * Create the sender queue including the thread that manages the queue.
 *
 * @return the SCH_ReceiverQueue or NULL.
 *
 * @since 0.3.0
 */
SCH_ReceiverQueue* createSCHReceiverQueue(ServerConnectionHandler*
                                                                 srvConnHandler)
{
  SCH_ReceiverQueue* queue = malloc(sizeof(SCH_ReceiverQueue));
  if (queue != NULL)
  {
    if (initMutex(&queue->mutex))
    {
      if (!initCond(&queue->condition))
      {
        releaseMutex(&queue->mutex);
        free(queue);
        queue = NULL;
      }
    }
    else
    {
      free(queue);
      queue = NULL;
    }

    if (queue != NULL)
    {
      queue->head    = NULL;
      queue->tail    = NULL;
      queue->size    = 0;
      queue->running = false;
      queue->svrConnHandler = srvConnHandler;
    }
  }

  return queue;
}

/**
 * Stops the queue is not already stopped and frees all memory associated with
 * it.
 *
 * @param queue The queue itself
 *
 * @since 0.3.0
 */
void releaseSCHReceiverQueue(SCH_ReceiverQueue* queue)
{
  LOG(LEVEL_INFO, "Enter release Server Connection Handler Receiver Queue...");

  if (queue == NULL)
  {
    RAISE_SYS_ERROR("Server Connection Handler receiver queue is not "
                    "initialized!");
  }
  else
  {
    if (queue->running)
    {
      // Stops and cleans the queue
      stopSCHReceiverQueue(queue);
    }
    if (queue->head != NULL)
    {
      RAISE_SYS_ERROR("Queue should be already empty!");
    }
    releaseMutex(&queue->mutex);
    destroyCond(&queue->condition);
    queue->svrConnHandler = NULL;
    free (queue);
  }

  LOG(LEVEL_INFO, ".. Exit release Server Connection Handler Receiver Queue!");
}

/**
 * The thread loop of the queue. To stop the queue call stopSendQueue()
 *
 * @param The queue itself
 *
 * @return NULL
 *
 * @since 0.3.0
 */
void* schReceiverQueueThreadLoop(void* thisQueue)
{
  SCH_ReceiverQueue* queue = (SCH_ReceiverQueue*)thisQueue;
  if (queue == NULL)
  {
    RAISE_SYS_ERROR("Server Connection Handler Receiver Queue is not "
                    "initialized!");
  }
  else
  {
    SCH_ReceiverQueueElement* packet = NULL;
    LOG(LEVEL_DEBUG, "Enter loop of Server Connection Handler Receiver Queue.");
    while (queue->running)
    {
      packet = fetchSCHReceiverPacket(queue);
      if (packet != NULL)
      {
        _handlePacket(packet->svrSock, packet->client, packet->pdu,
                      packet->size, queue->svrConnHandler);
        free(packet->pdu);
        free(packet);
      }
    }
    LOG(LEVEL_DEBUG, "Exit loop of Server Connection Handler REceiver Queue!");
  }

  return NULL;
}

/**
 * Start the send queue. In case the queue is already started this method does
 * not further start it.
 *
 * @return true if the Queue is running.
 *
 * @since 0.3.0
 */
bool startSCHReceiverQueue(SCH_ReceiverQueue* queue)
{
  bool retVal = false;

  if (queue == NULL)
  {
    RAISE_SYS_ERROR("Server Connection Handler Receiver Queue is not "
                    "initialized!");
  }
  else
  {
    lockMutex(&queue->mutex);
    if (!queue->running)
    {
      queue->running = true;
      if (pthread_create(&queue->handler, NULL, schReceiverQueueThreadLoop,
                         queue) != 0)
      {
        queue->running = false;
        RAISE_SYS_ERROR("Could not start the Server Connection Handler Receiver"
                        " queue!");
      }
    }

    retVal = queue->running;
    unlockMutex(&queue->mutex);
  }
  return retVal;
}

/**
 * Stop the queue but does not destroy the thread itself.
 *
 * @since 0.3.0
 */
void stopSCHReceiverQueue(SCH_ReceiverQueue* queue)
{
  if (queue == NULL)
  {
    RAISE_SYS_ERROR("Server Connection Handler Receiver queue is not "
                    "initialized!");
  }
  else
  {
    lockMutex(&queue->mutex);
    if (queue->running)
    {
      queue->running = false;
      // Stop the queue by waking it up
      LOG(LEVEL_DEBUG, "stopSCHReceiverQueue: send notification...");
      signalCond(&queue->condition);
    }
    unlockMutex(&queue->mutex);
    // Give the queue thread a chance to process the notify or run into a
    // wait timeout.
    LOG(LEVEL_DEBUG, "stopSCHReceiverQueue: sleep for %u ms",
                    SCH_RECEIVE_QUEUE_WAIT_MS * 2);
    usleep(SCH_RECEIVE_QUEUE_WAIT_MS * 2);

    lockMutex(&queue->mutex);
    // Free the remainder of the queue.
    LOG(LEVEL_DEBUG, "stopSCHReceiverQueue: wait for queue thread to join...");
    pthread_join(queue->handler, NULL);
    LOG(LEVEL_DEBUG, "schReceiverQueueThreadLoop STOPPED. Empty remainder of "
                    "queue!");
    SCH_ReceiverQueueElement* packet = NULL;
    while (queue->head != NULL)
    {
      packet = queue->head;
      queue->head = (SCH_ReceiverQueueElement*)packet->next;
      // Free the allocated memory
      free(packet->pdu);
      free(packet);
      queue->size--;
    }
    queue->tail = NULL;
    unlockMutex(&queue->mutex);
  }
}

/**
 * Retrieve the next packet from the queue as long as the queue is running.
 * in case the queue is not running this method returns NULL.
 *
 * @return  the next packet of NULL if the queue is empty.
 *
 * @since 0.3.0
 */
SCH_ReceiverQueueElement* fetchSCHReceiverPacket(SCH_ReceiverQueue* queue)
{
  SCH_ReceiverQueueElement* packet = NULL;

  if (queue != NULL)
  {
    lockMutex(&queue->mutex);
    while (queue->size == 0 && queue->running)
    {
      // wait until notify is called or after a timeout.
      waitCond(&queue->condition, &queue->mutex, SCH_RECEIVE_QUEUE_WAIT_MS);
      if(!queue->running) 
      {
        LOG(LEVEL_INFO, "Server Connection Handler Receiver Queue received "
                        "shutdown!");
      }
    }

    // If queue is still running and a packet is available take it
    if (queue->running && queue->head != NULL)
    {
      packet = queue->head;
      queue->size--;
      queue->head = (SCH_ReceiverQueueElement*)packet->next;
      packet->next = NULL;
    }
    unlockMutex(&queue->mutex);
  }
  return packet;
}

/**
 * Queue a copy of the the packet and return the size of the queue. The copy of
 * the packet will be freed by the queue handler thread itself.
 *
 * @param pdu The received PDU to be added to the queue. ( A copy will be
 *            created and stored)
 * @param svrSoc The server socket
 * @param client The client to received from
 * @param size The size of the PDU
 * @param queue The queue to be added to
 *
 * @return true if the packet was queued, otherwise false.
 *
 * @since 0.3.0
 */
bool addToSCHReceiverQueue(uint8_t* pdu, ServerSocket* svrSoc,
                           ServerClient* client, size_t size,
                           SCH_ReceiverQueue* queue)
{
  SCH_ReceiverQueueElement* packet = malloc(sizeof(SCH_ReceiverQueueElement));
  bool retVal = false;

  lockMutex(&queue->mutex);
  if (packet != NULL)
  {
    memset(packet, 0, sizeof(SCH_ReceiverQueueElement));
    packet->pdu = malloc(size);
    if (packet->pdu == NULL)
    {
      free(packet);
    }
    else
    {
      retVal = true;
      packet->svrSock  = svrSoc;
      packet->client   = client;
      packet->next     = NULL;
      packet->size     = size;
      memcpy(packet->pdu, pdu, size);
      if (queue->size == 0)
      {
        queue->head = packet;
        queue->tail = packet;
      }
      else
      {
        queue->tail->next = packet;
        queue->tail = packet;
      }
      queue->size++;
      // Signal a new packet is in the queue
      signalCond(&queue->condition);
    }
  }
  unlockMutex(&queue->mutex);

  if (!retVal)
  {
    RAISE_SYS_ERROR("Not enough memory to queue packets in send queue!");
  }

  return retVal;
}


////////////////////////////////////////////////////////////////////////////////
// The Server Connection Handler (SCH)
////////////////////////////////////////////////////////////////////////////////
/**
 * Initialized the connection handler and creates a server-socket and
 * binds it to the port specified in the system configuration.
 *
 * @param self The connection handler to be initialized. It is required that the
 *             connection handler is already instantiated (memory is allocated)
 * @param updCache Reference to the update cache. the cache MUST NOT be accessed
 *                 for writing, only reading.
 * @param sysConfig The system configuration.
 *
 * @return true if the handler could be initialized properly, otherwise false
 */
bool createServerConnectionHandler(ServerConnectionHandler* self,
                                   UpdateCache* updCache,
                                   AspathCache* aspathCache,
                                   Configuration* sysConfig,
                                   SKI_CACHE* skiCache)
{
  bool cont = true;
  self->inShutdown = false;
  self->receiverQueue = NULL; // For now set it to NULL

  if (updCache == NULL)
  {
    RAISE_SYS_ERROR("The update cache is NULL!");
    cont = false;
  }
  if (sysConfig == NULL)
  {
    RAISE_SYS_ERROR("The system configuration is NULL!");
    cont = false;
  }
  if (skiCache == NULL)
  {
    RAISE_SYS_ERROR("The SKI cache is NULL!");
    cont = false;
  }

  if (cont)
  {
    initSList(&self->clients);
    if (createServerSocket(&self->svrSock, sysConfig->server_port,
                           sysConfig->verbose))
    {
      // initialize and configure the proxyMap
      memset(self->proxyMap, 0, (sizeof(ProxyClientMapping)*256));
      if (!configureProxyMap(self, sysConfig->mapping_routerID))
      {
        LOG(LEVEL_ERROR, "Could not configure the Proxy-Mapping!");
        // Still keep on going. The configuration might have been faulty!
      }

      self->updateCache = updCache;
      self->aspathCache = aspathCache;
      self->skiCache = skiCache;
      self->sysConfig = sysConfig;

      if (!sysConfig->mode_no_receivequeue)
      {
        // Enable the receiver queue
        SCH_ReceiverQueue* queue = createSCHReceiverQueue(self);
        if (queue == NULL)
        {
          RAISE_SYS_ERROR("Could not create the Server Connection Handler "
                          "Receiver Queue.");
        }
        else
        {
          if (startSCHReceiverQueue(queue))
          {
            self->receiverQueue = queue;
          }
          else
          {
            // Free the allocated memory again
            free(queue);
          }
        }
      }
    }
    else
    {
      cont = false;
      releaseSList(&self->clients);
    }
  }
  return cont;
}

/**
 * Frees allocated resources.
 *
 * @param self The connection handler itself
 */
void releaseServerConnectionHandler(ServerConnectionHandler* self)
{
  if (self->receiverQueue != NULL)
  {
    // in case no receiver queue is used, the value is NULL
    SCH_ReceiverQueue* queue = (SCH_ReceiverQueue*)self->receiverQueue;
    stopSCHReceiverQueue(queue);
    releaseSCHReceiverQueue(queue);
  }

  releaseSList(&self->clients);
  memset(self->proxyMap, 0, (sizeof(ProxyClientMapping)*256));
}

/**
 * This method processes the validation result request. This method is called by
 * the packet handler and if necessary the request will be added to the command
 * queue. This method does NOT send error packets to the proxy!
 *
 * @param self The server connection handler.
 * @param svrSock The server socket used to send a possible validation request
 *                receipt
 * @param client The client instance where the packet was received on
 * @param updateCache The instance of the update cache
 * @param hdr The validation request header
 *
 * @return false if an internal (fatal) error occurred, otherwise true.
 */
bool processValidationRequest(ServerConnectionHandler* self,
                              ServerSocket* svrSock, ClientThread* client,
                              SRXRPOXY_BasicHeader_VerifyRequest* hdr)
{
  LOG(LEVEL_DEBUG, HDR "Enter processValidationRequest", pthread_self());

  bool retVal = true;

  // Determine if a receipt is requested and a result packet must be send
  bool     receipt =    (hdr->flags & SRX_FLAG_REQUEST_RECEIPT)
                      == SRX_FLAG_REQUEST_RECEIPT;
  // prepare already the send flag. Later on, if this is > 0 send a response.
  uint8_t  sendFlags = hdr->flags & SRX_FLAG_REQUEST_RECEIPT;

  bool     doOriginVal = (hdr->flags & SRX_FLAG_ROA) == SRX_FLAG_ROA;
  bool     doPathVal   = (hdr->flags & SRX_FLAG_BGPSEC) == SRX_FLAG_BGPSEC;
  bool     doAspaVal   = (hdr->flags & SRX_FLAG_ASPA) == SRX_FLAG_ASPA;

  bool      v4     = hdr->type == PDU_SRXPROXY_VERIFY_V4_REQUEST;
  // Set the BGPsec data
//  uint16_t bgpsecDataLen = 0;
//  BGPSecData bgpsecData;
//  bgpsecData.length = 0;
//  bgpsecData.data   = (uint8_t*)hdr+(v4 ? sizeof(SRXPROXY_VERIFY_V4_REQUEST)
//                                        : sizeof(SRXPROXY_VERIFY_V6_REQUEST));

  uint32_t requestToken = receipt ? ntohl(hdr->requestToken)
                                  : DONOTUSE_REQUEST_TOKEN;
  uint32_t originAS = 0;
  SRxUpdateID collisionID = 0;
  SRxUpdateID updateID = 0;

  bool doStoreUpdate = false;
  IPPrefix* prefix = NULL;
  // Specify the client id as a receiver only when validation is requested.
  uint8_t clientID = (doOriginVal || doPathVal || doAspaVal) ? client->routerID : 0;

  // 1. Prepare for and generate the ID of the update
  prefix = malloc(sizeof(IPPrefix));
  memset(prefix, 0, sizeof(IPPrefix));
  prefix->length     = hdr->prefixLen;
  BGPSecData bgpData;
  memset (&bgpData, 0, sizeof(BGPSecData));
  // initialize the val pointer - it will be adjusted within the correct
  // request type.
  uint8_t* valPtr = (uint8_t*)hdr;
  AS_TYPE     asType;
  AS_REL_DIR  asRelDir;
  AS_REL_TYPE asRelType;
  if (v4)
  {
    SRXPROXY_VERIFY_V4_REQUEST* v4Hdr = (SRXPROXY_VERIFY_V4_REQUEST*)hdr;
    valPtr += sizeof(SRXPROXY_VERIFY_V4_REQUEST);
    prefix->ip.version  = 4;
    prefix->ip.addr.v4  = v4Hdr->prefixAddress;
    originAS            = ntohl(v4Hdr->originAS);
    // The next two are in host format for convenience
    bgpData.numberHops  = ntohs(v4Hdr->bgpsecValReqData.numHops);
    bgpData.attr_length = ntohs(v4Hdr->bgpsecValReqData.attrLen);
    // Now in network format as required.
    bgpData.afi         = v4Hdr->bgpsecValReqData.valPrefix.afi;
    bgpData.safi        = v4Hdr->bgpsecValReqData.valPrefix.safi;
    bgpData.local_as    = v4Hdr->bgpsecValReqData.valData.local_as;
    asType              = v4Hdr->common.asType;
    asRelType           = v4Hdr->common.asRelType;
  }
  else
  {
    SRXPROXY_VERIFY_V6_REQUEST* v6Hdr = (SRXPROXY_VERIFY_V6_REQUEST*)hdr;
    valPtr += sizeof(SRXPROXY_VERIFY_V6_REQUEST);
    prefix->ip.version  = 6;
    prefix->ip.addr.v6  = v6Hdr->prefixAddress;
    originAS            = ntohl(v6Hdr->originAS);
    // The next two are in host format for convenience
    bgpData.numberHops  = ntohs(v6Hdr->bgpsecValReqData.numHops);
    bgpData.attr_length = ntohs(v6Hdr->bgpsecValReqData.attrLen);
    // Now in network format as required.
    bgpData.afi         = v6Hdr->bgpsecValReqData.valPrefix.afi;
    bgpData.safi        = v6Hdr->bgpsecValReqData.valPrefix.safi;
    bgpData.local_as    = v6Hdr->bgpsecValReqData.valData.local_as;
    //asType           = ntohl(v6Hdr->asType);
    //asRelType        = ntohl(v6Hdr->asRelType);
  }


  // Check if AS path exists and if so then set it
  if (bgpData.numberHops != 0)
  {
    bgpData.asPath = (uint32_t*)valPtr;
  }
  // Check if BGPsec path exits and if so then set it
  if (bgpData.attr_length != 0)
  {
    // BGPsec attribute comes after the as4 path
    bgpData.bgpsec_path_attr = valPtr + (bgpData.numberHops * 4);
  }
  


  // 2. Generate the CRC based updateID
  updateID = generateIdentifier(originAS, prefix, &bgpData);
  // test for collision and attempt to resolve
  collisionID = updateID;
  while(detectCollision(self->updateCache, &updateID, prefix, originAS, 
                        &bgpData))
  {
    updateID++;
  }
  if (collisionID != updateID)
  {
    LOG(LEVEL_NOTICE, "UpdateID collision detected!!. The original update ID"
      " could have been [0x%08X] but was changed to a collision free ID "
      "[0x%08X]!", collisionID, updateID);
  }

  //  3. Try to find the update, if it does not exist yet, store it.
  SRxResult        srxRes;
  SRxDefaultResult defResInfo;
  // The method getUpdateResult will initialize the result parameters and
  // register the client as listener (only if the update already exists)
  ProxyClientMapping* clientMapping = clientID > 0 ? &self->proxyMap[clientID]
                                                   : NULL;

  uint32_t pathId = 0;

  doStoreUpdate = !getUpdateResult (self->updateCache, &updateID,
                                    clientID, clientMapping,
                                    &srxRes, &defResInfo, &pathId);
  
  LOG(LEVEL_INFO, FILE_LINE_INFO "\033[1;33m ------- Received ASpath info ------- \033[0m");
  LOG(LEVEL_INFO, "     updateId: [0x%08X] pathID: [0x%08X] "
      " AS Type: %s  AS Relationship: %s", 
      updateID, pathId, 
      asType==2 ? "AS_SEQUENCE": (asType==1 ? "AS_SET": "ETC"),
      asRelType == 2 ? "provider" : (asRelType == 1 ? "customer":         
        (asRelType == 3 ? "sibling": (asRelType == 4 ? "lateral" : "unknown"))));

  AS_PATH_LIST *aspl;
  SRxResult srxRes_aspa; 
  bool modifyUpdateCacheWithAspaValue = false;

  switch (asRelType)
  {
    case AS_REL_CUSTOMER:
      asRelDir = ASPA_UPSTREAM; break;
    case AS_REL_PROVIDER:
      asRelDir = ASPA_DOWNSTREAM; break;
    case AS_REL_SIBLING:
      asRelDir = ASPA_DOWNSTREAM; break;
    case AS_REL_LATERAL:
      asRelDir = ASPA_UPSTREAM; break;
    default:
      asRelDir = ASPA_UNKNOWNSTREAM;     
  }


  if (pathId == 0)  // if not found in  cEntry
  {
    pathId = makePathId(bgpData.numberHops, bgpData.asPath, asType, true);
    LOG(LEVEL_INFO, FILE_LINE_INFO " generated Path ID : %08X ", pathId);

    // to see if there is already exist or not in AS path Cache with path id
    aspl = getAspathListFromAspathCache (self->aspathCache, pathId, &srxRes_aspa);
    
    // AS Path List already exist in Cache
    if(aspl)
    {
      // once found aspa result value in Cache, no need to validate operation
      //  this value is some value not undefined
      if (srxRes_aspa.aspaResult == SRx_RESULT_UNDEFINED)
      {
        LOG(LEVEL_INFO, FILE_LINE_INFO " Already registered with the previous pdu");
      }
      else
      {
        // in case the same update message comes from same peer, even though same update, 
        // bgpsec pdu is different, so that it results in a new updateID, which in turn 
        // makes not found in updatecahe. So this case makes not found pathId, but aspath cache 
        // stores srx result value in db with the matched path id. So srxRes_aspa.aspaResult is
        // not undefined
        LOG(LEVEL_INFO, FILE_LINE_INFO " ASPA validation Result[%d] is already exist", srxRes_aspa.aspaResult);

        // Modify UpdateCache's srx Res -> aspaResult with srxRes_aspa.aspaResult
        // But UpdateCache's cEntry here dosen't exist yet
        // so, after calling storeUpdate, put this value into cEntry directly
        modifyUpdateCacheWithAspaValue = true;
      }

      srxRes.aspaResult = srxRes_aspa.aspaResult;

    }
    // AS Path List not exist in Cache
    else
    {
      aspl = newAspathListEntry(bgpData.numberHops, bgpData.asPath, pathId, asType, asRelDir, bgpData.afi, true);
      if(!aspl)
      {
        LOG(LEVEL_ERROR, " memory allocation for AS path list entry resulted in fault");
        //return false;
      }
  
      if (doStoreUpdate)
      {
        defResInfo.result.aspaResult = hdr->aspaDefRes; // router's input value (Undefined, Unverifiable, Invalid)
        defResInfo.resSourceASPA     = hdr->aspaResSrc;
      }

      // in order to free aspl, need to copy value inside the function below
      //
      storeAspathList(self->aspathCache, &defResInfo, pathId, asType, aspl);
      srxRes.aspaResult   = defResInfo.result.aspaResult;

    }
    // free 
    if (aspl)
      deleteAspathListEntry(aspl);
  }
      

  // -------------------------------------------------------------------

  if (doStoreUpdate)
  {
    //TODO: Normally an update should be validated all the time. Maybe the
    // update registration should be about the validation type. This way
    // one can filter for what to listen for.

    // TODO Check the store only in the spec. It might not make much sense at
    // all. or if store only, the update will not be registered with the client?
    // This allows a loading of the cache and starting to validate without
    // a client attached. -> Or what about client 0 or 255??

    // Copy the information of the default result. Just store them as they are
    // provided with. -- it could be a store only without validation request!
    // In this case check discussion on twiki
    defResInfo.result.roaResult    = hdr->roaDefRes;
    defResInfo.resSourceROA        = hdr->roaResSrc;

    defResInfo.result.bgpsecResult = hdr->bgpsecDefRes;
    defResInfo.resSourceBGPSEC     = hdr->bgpsecResSrc;


    if (!storeUpdate(self->updateCache, clientID, clientMapping,
              &updateID, prefix, originAS, &defResInfo, &bgpData, pathId))
    {
      RAISE_SYS_ERROR("Could not store update [0x%08X]!!", updateID);
      // Maybe check for ID conflict, if not then get result again - or just
      // quit here!
      free(prefix);
      return false;
    }

    // Use the default result.
    srxRes.roaResult    = defResInfo.result.roaResult;
    srxRes.bgpsecResult = defResInfo.result.bgpsecResult;
  }
  free(prefix);
  prefix = NULL;

  if (modifyUpdateCacheWithAspaValue)
  {
    // modify UpdateCache with srxRes_aspa.aspaResult, then later this value 
    // in UpdateCahe will be used 
    modifyUpdateCacheResultWithAspaVal(self->updateCache, &updateID, &srxRes_aspa);

  }

  // Just check if the client has the correct values for the requested results
  if (doOriginVal && (hdr->roaDefRes != srxRes.roaResult))
  {
    sendFlags = sendFlags | SRX_FLAG_ROA;
  }
  if (doPathVal && (hdr->bgpsecDefRes != srxRes.bgpsecResult))
  {
    sendFlags = sendFlags | SRX_FLAG_BGPSEC;
  }

  if (sendFlags > 0) // a notification is needed. flags specifies the type
  {
    // TODO: Check specification if we can send a receipt without results, if
    // not the following 6 lines MUST be included, otherwise not.
    if (doOriginVal)
    {
      sendFlags = sendFlags | SRX_FLAG_ROA;
    }
    if (doPathVal)
    {
      sendFlags = sendFlags | SRX_FLAG_BGPSEC;
    }
    if (doAspaVal)
    {
      sendFlags = sendFlags | SRX_FLAG_ASPA;
    }
    
    // Now send the results we know so far;
    if (!sendVerifyNotification(svrSock, client, updateID, sendFlags,
                                requestToken, srxRes.roaResult,
                                srxRes.bgpsecResult, srxRes.aspaResult,
                                !self->sysConfig->mode_no_sendqueue))
    {
      RAISE_ERROR("Could not send the initial verify notification for update"
        "[0x%08X] to client [0x%02X]!", updateID, client->routerID);
      retVal = false;
    }
  }

  // Now check if validation has to be performed again - In the case the 
  // update was already stored and validated, the appropriate sendFlags does 
  // not have the flags set and no additional validation has to be performed at 
  // this point therefore also filter for sendFlags, the command handler will
  // do it otherwise and we can save this effort.
  if ((doOriginVal || doPathVal || doAspaVal) && ((sendFlags & SRX_FLAG_ROA_BGPSEC_ASPA) > 0))
  {
    // Only keep the validation flags.
    hdr->flags = sendFlags & SRX_FLAG_ROA_BGPSEC_ASPA;

    // create the validation command!
    if (!queueCommand(self->cmdQueue, COMMAND_TYPE_SRX_PROXY, svrSock, client,
                      updateID, ntohl(hdr->length), (uint8_t*)hdr))
    {
      RAISE_ERROR("Could not add validation request to command queue!");
      retVal = false;
    }
  }

  LOG(LEVEL_DEBUG, HDR "Exit processValidationRequest", pthread_self());
  return retVal;
}

#define MAX_BLOCKS 16
#define HASH_LEN SHA256_DIGEST_LENGTH

bool verify_signature(const uint8_t* hash, size_t hash_len, 
                      const uint8_t* signature, size_t sig_len, 
                      uint32_t asn){
  if (hash == NULL || signature == NULL || hash_len != SHA256_DIGEST_LENGTH) {
      fprintf(stderr, "Invalid input to signature verification.\n");
      return false;
  }

  // print input for debugging
  printf("Hash: ");
  for (size_t i = 0; i < hash_len; i++) {
      printf("%02x", hash[i]);
  }
  printf("\nSignature: ");
  for (size_t i = 0; i < sig_len; i++) {
      printf("%02x", signature[i]);
  }
  printf("\nASN: %u\n", asn);
  


  // Step 1: Load the public key
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  printf("Validating signature for ASN: %u\n", asn);
  const char* publicKeyDir = "/home/nils/Dokumente/ASPA+/NIST-BGP-SRx/examples/bgpsec-keys/raw-keys/";
  char certPath[512];
  snprintf(certPath, sizeof(certPath), "%s%u.cert", publicKeyDir, asn);

  FILE* file = fopen(certPath, "rb");
  if (!file) {
      fprintf(stderr, "Certificate file not found: %s\n", certPath);
      return false;
  }

  // Step 2: Load X.509 certificate
  X509* cert = d2i_X509_fp(file, NULL);
  fclose(file);
  if (!cert) {
      fprintf(stderr, "Failed to parse certificate from file: %s\n", certPath);
      return false;
  }

  // Step 3: Extract public key
  EVP_PKEY* pubkey = X509_get_pubkey(cert);
  X509_free(cert);
  if (!pubkey) {
      fprintf(stderr, "Failed to extract public key from cert\n");
      return false;
  }

  EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pubkey);
    EVP_PKEY_free(pubkey);
    if (!ecKey) {
        fprintf(stderr, "Failed to get EC_KEY from EVP_PKEY\n");
        return false;
    }

  // Step 4: Validate the given hash and signature
  // Note: The hash should be the SHA-256 hash of the message that was signed.
  int verify_status = ECDSA_verify(0, hash, hash_len, signature, sig_len, ecKey);
  EC_KEY_free(ecKey);

  if (verify_status == 1) {
    printf("✅ Signature is valid.\n");
    return true;
  } else if (verify_status == 0) {
      printf("❌ Signature is invalid.\n");
      return false;
  } else {
      // verify_status == -1, an error occurred
      fprintf(stderr, "🚨 Signature verification failed due to internal error.\n");
      ERR_print_errors_fp(stderr); // OpenSSL error output
      return false;
  }
 return true; // For now, always return true for testing purposes
}


static bool processSigtraValidationRequest(ServerConnectionHandler* self,
                              ServerSocket* svrSock, ClientThread* client,
                              SRXPROXY_SIGTRA_VALIDATION_REQUEST* validation_request)
{
  bool retVal = true;
  // Array is in Strucutred: [lastHop,..,.., Origin]

  SRXPROXY_SIGTRA_VALIDATION_REQUEST* req = validation_request;
  uint32_t request_identifier = ntohl(req->signature_identifier);
  uint8_t count = req->blockCount;
  uint8_t  prefixLen = req->prefixLen;
  uint32_t prefix    = ntohl(req->prefix);
  uint8_t  asPathLen = req->asPathLen;
  static uint32_t localAsPath[16]      = {0};
  for (int i = 0; i < asPathLen && i < 16; i++) {
      localAsPath[i] = ntohl(req->asPath[i]);
  }
  uint32_t otcField  = ntohs(req->otcField);
  uint32_t originAs = localAsPath[asPathLen - 1];
  

  // Print received data
  printf("\n\n\n");
  printf("\n--- Received SRXPROXY_SIGTRA_VALIDATION_REQUEST ---\n");
  // print identifier
  printf("Identifier:      %u\n", request_identifier);
  // print extracted block count 
  printf("Prefix Length:   %u\n", prefixLen);
  printf("Prefix:          %u.%u.%u.%u (raw: 0x%08x)\n",
        (prefix >> 24) & 0xFF, (prefix >> 16) & 0xFF,
        (prefix >> 8) & 0xFF, prefix & 0xFF, prefix);

  printf("AS Path Length:  %u\n", asPathLen);
  for (int i = 0; i < asPathLen && i < 16; i++) {
      printf("  AS Path[%d]:     %u\n", i, localAsPath[i]);
  }
  printf("Origin AS:      %u\n", originAs);
  printf("OTC Field:      %u\n", otcField);
  printf("Block Count:    %d\n", count);
  printf("---------------------------------------------------\n\n");


  // Initial Hash = Hash(Origin || Prefix || PrefixLen || OTCField)
  uint8_t initialHash[SHA256_DIGEST_LENGTH];
  uint8_t initialInput[sizeof(uint32_t) * 4 + sizeof(uint8_t)];
  size_t offset = 0;
  memcpy(initialInput + offset, &originAs, sizeof(uint32_t)); offset += sizeof(uint32_t);
  memcpy(initialInput + offset, &prefix, sizeof(uint32_t)); offset += sizeof(uint32_t);
  memcpy(initialInput + offset, &prefixLen, sizeof(uint8_t)); offset += sizeof(uint8_t);
  memcpy(initialInput + offset, &otcField, sizeof(uint32_t)); offset += sizeof(uint32_t);
  SHA256(initialInput, offset, initialHash);
  printf("Initial Hash: ");
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      printf("%02x", initialHash[i]);
  }
  printf("\n");

  // Pointer math to get first block
  uint8_t* raw = (uint8_t*)validation_request;
  SRXPROXY_SIGTRA_BLOCK* blocks = (SRXPROXY_SIGTRA_BLOCK*)(raw + sizeof(SRXPROXY_SIGTRA_VALIDATION_HEADER));

  for (uint8_t i = 0; i < count; i++)
  {
    // Extract all fields for current block
    SRXPROXY_SIGTRA_BLOCK* block = &blocks[i];
    printf("Raw block dump:\n");
    const uint8_t* raw = (const uint8_t*)block;
    for (size_t k = 0; k < sizeof(SRXPROXY_SIGTRA_BLOCK); k++) {
        printf("%02x ", raw[k]);
        if ((k+1) % 16 == 0) printf("\n");
    }
    printf("\n");

    uint8_t block_id = block->id;
    uint32_t signature_length = ntohl(block->signatureLength);
    uint32_t timestamp = ntohl(block->timestamp);
    uint32_t nextASN = ntohl(block->nextASN);
    uint32_t creatorAS = ntohl(block->creatingAS);
    uint8_t ski[20];
    memcpy(ski, block->ski, sizeof(block->ski));
    printf("SKI: ");
    for (size_t j = 0; j < sizeof(ski); j++) {
        printf("%02x", ski[j]);
    }
    printf("\n");
    
    // print block fields:
    printf("\n-- Block %d --\n", i);
    printf("Identifier:     %u\n", block_id);
    printf("Signature Length: %u\n", signature_length);
    printf("Signature:      ");
    for (size_t j = 0; j < sizeof(block->signature); j++) {
    printf("%02x", block->signature[j]);
}
    printf("[...]\n");
    printf("Timestamp:      %u\n", timestamp);
    printf("Creating AS:    %u\n", creatorAS);
    printf("Next ASN:       %u\n", nextASN);
    printf("SKI:            ");
    // print ski:
    for (size_t j = 0; j < sizeof(block->ski); j++) {
        printf("%02x", block->ski[j]);
    }
    printf("\n");
    bool continueProcessing = false;
    if (i == 0)  {
      // Find the first signing AS in the AS path
      // Hash = Hash(H_(i-1) || timestamp || ski || creatingAS || nextASN)

      for (uint8_t q = 0; q < asPathLen; q++) {
        if (localAsPath[q] == creatorAS) {
          printf("Found first signing AS %u at position %d in AS path\n", creatorAS, q);
          
          // Calculate first hash
          // Hash = Hash(H_(i-1) || timestamp || ski || creatingAS || nextASN)
          uint8_t input[SHA256_DIGEST_LENGTH + sizeof(uint32_t) * 3 + 20];
          size_t pos = 0;
          memcpy(input + pos, initialHash, SHA256_DIGEST_LENGTH); pos += SHA256_DIGEST_LENGTH;
          memcpy(input + pos, &block->timestamp, sizeof(uint32_t)); pos += sizeof(uint32_t);
          memcpy(input + pos, block->ski, 20); pos += 20;
          memcpy(input + pos, &block->creatingAS, sizeof(uint32_t)); pos += sizeof(uint32_t);
          memcpy(input + pos, &block->nextASN, sizeof(uint32_t)); pos += sizeof(uint32_t);
          uint8_t hash[SHA256_DIGEST_LENGTH];
          SHA256(input, pos, hash);
          printf("\nBlock %d Hash:   ", i);
          for (size_t j = 0; j < SHA256_DIGEST_LENGTH; j++) {
              printf("%02x", hash[j]);
          }
          printf("\n");
          printf("Done with Block %d (Creating AS %u)\n", i, creatorAS);

          // Validate the signature of the first block
          bool valid = verify_signature(
              hash, SHA256_DIGEST_LENGTH,
              block->signature, sizeof(block->signature),
              creatorAS
          );

          printf("Signature for Block %d is %s\n", i, valid ? "valid" : "invalid");
          continueProcessing = true;
        }
      } 
      if (!continueProcessing) {
        printf("No signing AS found in AS path for Block %d\n", i);
        return false; 
      }
    }
    else
    {
      // Hash = Hash(H_(i-1) || timestamp || ski || creatingAS || nextASN)
      // H1=Hash(ASPath[:i] || Prefix || PrefixLen || OTCField)
      // H2=Hash(H1 || blocks[:i])
      // H3=Hash(H2 || blocks[i].timestamp || blocks[i].ski || blocks[i].creatingAS || blocks[i].nextASN)

      // Step 1: Get the AS path up to the current block
      printf("ASpathlen: %d\n", asPathLen);

      for (int j = asPathLen - 1; j >= 0; j--){
        printf("Comparing AS Path[%d]: %u with creatingAS: %u\n", j, localAsPath[j], creatorAS);
        if (localAsPath[j] == creatorAS) {
          printf("Working wiht index %d\n", j);
          // Found the current AS: create aspath up to this point (including it)
          int sizeOfAsPathUpToCurrent = asPathLen - j;
          uint32_t asPathUpToCurrent[sizeOfAsPathUpToCurrent];
          printf("Caluclated size of AS Path up to current: %d\n", sizeOfAsPathUpToCurrent);
          int index = 0;
          size_t asPathOffset = 0;
          for (int k = j; k < asPathLen; k++) {
            asPathUpToCurrent[index] = localAsPath[k];
            asPathOffset += sizeof(uint32_t);
            index++;
          }
          for (int i = 0; i < sizeOfAsPathUpToCurrent; i++) {
            printf("  AS Path[%d]:      %u\n", i, asPathUpToCurrent[i]);
          }
        
          // Step 2: Hash the AS path, prefix, prefix length, and OTC field
          uint8_t asPathHash[SHA256_DIGEST_LENGTH];
          uint8_t asPathInputFull[SHA256_DIGEST_LENGTH + sizeof(uint32_t) * 3 + sizeof(uint8_t)];
          size_t asPathInputOffset = 0;
          memcpy(asPathInputFull + asPathInputOffset, asPathUpToCurrent, asPathOffset);
          asPathInputOffset += asPathOffset;
          memcpy(asPathInputFull + asPathInputOffset, &prefix, sizeof(uint32_t));
          asPathInputOffset += sizeof(uint32_t);
          memcpy(asPathInputFull + asPathInputOffset, &prefixLen, sizeof(uint8_t));
          asPathInputOffset += sizeof(uint8_t);
          memcpy(asPathInputFull + asPathInputOffset, &otcField, sizeof(uint32_t));
          asPathInputOffset += sizeof(uint32_t);
          SHA256(asPathInputFull, asPathInputOffset, asPathHash);
          printf("AS Path Hash for block %d: ", i);
          for (size_t q = 0; q < SHA256_DIGEST_LENGTH; q++) {
              printf("%02x", asPathHash[q]);
          }
          printf("\n");
          
          size_t previousBlocksOffset = 0;
          size_t maxSize = sizeof(SRXPROXY_SIGTRA_BLOCK) * (i + 1);
          uint8_t* previousBlocksInput = malloc(maxSize);
          if (!previousBlocksInput) {
              fprintf(stderr, "Allocation failed!\n");
              exit(1);
          }
          for (uint8_t k = 0; k <= i; k++) {
            memcpy(previousBlocksInput + previousBlocksOffset, &blocks[k], sizeof(SRXPROXY_SIGTRA_BLOCK));
            previousBlocksOffset += sizeof(SRXPROXY_SIGTRA_BLOCK);
          }
          
          // Step 4: Hash the AS path hash and previous blocks
          uint8_t previousBlocksHash[SHA256_DIGEST_LENGTH];
          uint8_t previousBlocksInputFull[SHA256_DIGEST_LENGTH + previousBlocksOffset];
          size_t previousBlocksInputFullOffset = 0;
          memcpy(previousBlocksInputFull + previousBlocksInputFullOffset, asPathHash, SHA256_DIGEST_LENGTH);
          previousBlocksInputFullOffset += SHA256_DIGEST_LENGTH;
          memcpy(previousBlocksInputFull + previousBlocksInputFullOffset, previousBlocksInput, previousBlocksOffset);
          previousBlocksInputFullOffset += previousBlocksOffset;
          SHA256(previousBlocksInputFull, previousBlocksInputFullOffset, previousBlocksHash);
          printf("Previous Blocks Hash for block %d: ", i);
          for (size_t r = 0; r < SHA256_DIGEST_LENGTH; r++) {
              printf("%02x", previousBlocksHash[r]);
          }
          printf("\n");

          // Step 5: Hash the previous blocks hash with the current block's timestamp, ski, creatingAS, and nextASN
          uint8_t finalInput[SHA256_DIGEST_LENGTH + sizeof(uint32_t) * 3 + 20];
          size_t finalInputOffset = 0;
          memcpy(finalInput + finalInputOffset, previousBlocksHash, SHA256_DIGEST_LENGTH);    
          finalInputOffset += SHA256_DIGEST_LENGTH;
          memcpy(finalInput + finalInputOffset, &block->timestamp, sizeof(uint32_t));
          finalInputOffset += sizeof(uint32_t);
          memcpy(finalInput + finalInputOffset, block->ski, 20);
          finalInputOffset += 20;
          memcpy(finalInput + finalInputOffset, &block->creatingAS, sizeof(uint32_t));
          finalInputOffset += sizeof(uint32_t);
          memcpy(finalInput + finalInputOffset, &block->nextASN, sizeof(uint32_t));
          finalInputOffset += sizeof(uint32_t);
          uint8_t finalHash[SHA256_DIGEST_LENGTH];
          SHA256(finalInput, finalInputOffset, finalHash);
          printf("Final Hash for block %d: ", i);
          for (size_t t = 0; t < SHA256_DIGEST_LENGTH; t++) {
              printf("%02x", finalHash[t]);
          }
          printf("\n");

          // Step 6: Verify the signature
          // Calculate siganture length (not including the block, only got the signature)
          int sigLen = sizeof(block->signature);
          printf("Validating for ASN: %u with signature length: %d\n", creatorAS, sigLen);
          bool valid = verify_signature(
              finalInput, SHA256_DIGEST_LENGTH,
              block->signature, sizeof(block->signature),
              creatorAS
          );
          free(previousBlocksInput);
          break; // Exit the loop once we found the current AS in the path
        }
      }
      return false; // If we reach here, the current AS was not found in the path
    }
  }  
  return retVal;
}
void hexDump(const void* data, size_t size) {
  const uint8_t* byte = (const uint8_t*)data;
  for (size_t i = 0; i < size; i += 16) {
      printf("%04zx: ", i);
      for (size_t j = 0; j < 16 && i + j < size; j++) {
          printf("%02x ", byte[i + j]);
      }
      printf(" | ");
      for (size_t j = 0; j < 16 && i + j < size; j++) {
          char c = byte[i + j];
          printf("%c", (c >= 32 && c <= 126) ? c : '.');
      }
      printf("\n");
  }
}

/**
 * Convert a 40-character hex string to a 20-byte array.
 * Returns 0 on success, -1 on failure.
 */
int parseHexSKI(const char* hexStr, uint8_t* outSKI) {
  if (!hexStr || strlen(hexStr) != 40) {
      fprintf(stderr, "Invalid SKI string (must be 40 hex characters)\n");
      return -1;
  }

  for (int i = 0; i < 20; ++i) {
      char byteStr[3] = { hexStr[i*2], hexStr[i*2+1], '\0' };
      if (!isxdigit(byteStr[0]) || !isxdigit(byteStr[1])) {
          fprintf(stderr, "Invalid hex character in SKI: %s\n", byteStr);
          return -1;
      }
      outSKI[i] = (uint8_t) strtol(byteStr, NULL, 16);
  }
  return 0;
}

// helper stuct to hold the signature input
typedef struct {
  uint32_t otcField;     // 4 byte
  uint32_t prevASN;       // 4 bytes
  uint32_t currentASN;    // 4 bytes
  uint32_t nextASN;       // 4 bytes
  uint32_t timestamp;     // 4 bytes
  uint8_t  prefixLen;     // 1 byte
  uint32_t prefix;        // 4 bytes
} SignatureInput;

// Signature block
typedef struct {
  uint8_t signature[72];   // DER-encoded ECDSA signature
  unsigned int sigLen;
  uint32_t timestamp;
  uint8_t ski[20];         // Subject Key Identifier
  uint32_t asn;
  uint32_t nextASN;
} SignatureBlock;

bool signBGPMessageP256(const SignatureInput* input,
                        EC_KEY* ecKey,
                        const uint8_t* prevHash, size_t prevHashLen,
                        const uint8_t* prevSig, size_t prevSigLen,
                        const SignatureBlock* prevBlock,
                        const uint8_t* ski,
                        SignatureBlock* sigBlock)
{
  if (!input || !ecKey || !ski || !sigBlock) {
    fprintf(stderr, "Invalid input to signBGPMessageP256\n");
    return false;
  }

  // Step 1: Canonical base message (21 bytes total)
  uint8_t message[21];
  size_t offset = 0;
  memcpy(message + offset, &input->otcField, 4);   offset += 4;
  memcpy(message + offset, &input->prevASN, 4);    offset += 4;
  memcpy(message + offset, &input->currentASN, 4); offset += 4;
  memcpy(message + offset, &input->nextASN, 4);    offset += 4;
  memcpy(message + offset, &input->timestamp, 4);  offset += 4;
  memcpy(message + offset, &input->prefixLen, 1);  offset += 1;
  memcpy(message + offset, &input->prefix, 4);     offset += 4;

  // Step 2: Hash H_0 = SHA256(canonical message)
  uint8_t hash[SHA256_DIGEST_LENGTH];
  SHA256(message, sizeof(message), hash);

  // Step 3: If previous signature block exists, hash it into the chain
  if (prevHash && prevSig && prevBlock) {
    uint8_t chainInput[SHA256_DIGEST_LENGTH + 72 + 4 + 20 + 4 + 4];
    size_t pos = 0;

    memcpy(chainInput + pos, prevHash, prevHashLen); pos += prevHashLen;
    memcpy(chainInput + pos, prevSig, prevSigLen);   pos += prevSigLen;
    memcpy(chainInput + pos, &prevBlock->timestamp, 4); pos += 4;
    memcpy(chainInput + pos, prevBlock->ski, 20);    pos += 20;
    memcpy(chainInput + pos, &prevBlock->asn, 4);     pos += 4;
    memcpy(chainInput + pos, &prevBlock->nextASN, 4); pos += 4;

    SHA256(chainInput, pos, hash);  // hash is now H_n
  }

  // Step 4: Extend hash with current metadata
  uint8_t metaInput[SHA256_DIGEST_LENGTH + 4 + 20 + 4 + 4];
  size_t metaPos = 0;
  memcpy(metaInput + metaPos, hash, SHA256_DIGEST_LENGTH); metaPos += SHA256_DIGEST_LENGTH;
  memcpy(metaInput + metaPos, &input->timestamp, 4);       metaPos += 4;
  memcpy(metaInput + metaPos, ski, 20);                    metaPos += 20;
  memcpy(metaInput + metaPos, &input->currentASN, 4);      metaPos += 4;
  memcpy(metaInput + metaPos, &input->nextASN, 4);         metaPos += 4;

  // Step 5: Final hash for signing
  uint8_t finalHash[SHA256_DIGEST_LENGTH];
  SHA256(metaInput, metaPos, finalHash);

  // Step 6: Sign with ECDSA
  sigBlock->sigLen = sizeof(sigBlock->signature);
  if (ECDSA_sign(0, finalHash, SHA256_DIGEST_LENGTH, sigBlock->signature, &sigBlock->sigLen, ecKey) != 1) {
    fprintf(stderr, "ECDSA_sign failed\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  // Step 7: Fill SignatureBlock
  sigBlock->timestamp = input->timestamp;
  sigBlock->asn = input->currentASN;
  sigBlock->nextASN = input->nextASN;
  memcpy(sigBlock->ski, ski, 20);

  printf("Signature created! Len: %u bytes\n", sigBlock->sigLen);
  return true;
}


// --- Helper to generate EC Key (for testing) ---

EC_KEY* generateTestKey()
{
    // Generate a new EC key using the secp256r1 curve
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);  // secp256r1
    if (!key) {
      return NULL;
    }
    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        return NULL;
    }
    return key;
}



EC_KEY* load_ec_private_key_from_string(const char* key_string) {
  EC_KEY* eckey = NULL;
  BIO* keybio = NULL;
  //printf("OpenSSL Version Number (hex): 0x%lx\n", OpenSSL_version_num());
  //printf("Step 1: Creating BIO...2\n");
  //keybio = BIO_new_mem_buf(test_key_pem, (int)strlen(test_key_pem));
  if (!keybio) { 
      fprintf(stderr, "BIO creation failed\n"); 
      return NULL; 
  }

  // Step 2: Load the EC private key from the BIO
  eckey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
  if (!eckey) {
      fprintf(stderr, "Failed to read EC private key from BIO\n");
      ERR_print_errors_fp(stderr);
      BIO_free(keybio);
      return NULL;
  }

  // Step 3: Clean up BIO, as it's no longer needed
  BIO_free(keybio);
  return eckey;
}

// -- Helper for timestamp conversion --

uint64_t ntohll(uint64_t value) {
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      return ((uint64_t)ntohl(value & 0xFFFFFFFF) << 32) | ntohl(value >> 32);
  #else
      return value;
  #endif
  }


EC_KEY* load_ec_key_from_file(const char* filename) {
  FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open key file");
        return NULL;
    }

    EC_KEY* ec_key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!ec_key) {
        ERR_print_errors_fp(stderr); // Optional: Print OpenSSL errors
        return NULL;
    }

    return ec_key;
  }

/**
 * This method processes the signature generation request. For each requested peer,
 * a signature will be generated and send back to the client. 
 */
static bool processSigtraGenerationRequest(ServerConnectionHandler* self,
                                            ServerSocket* svrSock, ClientThread* client,
                                            SRXPROXY_SIGTRA_GENERATION_REQUEST* generation_request) 
  {
    bool retVal = true;
    SRXPROXY_SIGTRA_GENERATION_REQUEST* req = generation_request;

    // Extract fields from the request
    uint32_t signature_id     = ntohl(req->signature_identifier);  
    uint8_t  prefixLen        = req->prefixLen;
    uint32_t prefix           = ntohl(req->prefix);
    uint8_t  as_path_len      = req->asPathLen;
    static uint32_t as_path[16]      = {0};
    for (int i = 0; i < 16 && i < as_path_len; i++) {
          as_path[i] = ntohl(req->asPath[i]);
      }
    uint32_t originAS = ntohl(req->originAS);
    uint32_t timestamp = ntohl(req->timestamp);
    uint16_t otcField        = ntohl(req->otcField);
    uint8_t  peer_count       = req->peerCount;
    static uint32_t peers[16]        = {0};
    for (int i = 0; i < peer_count && i < 16; i++) {
        peers[i] = ntohl(req->peers[i]);
    }
    uint32_t requestingASN = ntohl(req->reqAS);
    uint8_t  blocks_count = req->blockCount;

    // ---------- Print All Data ---------- //
    printf("\n\n\n");
    printf("\n--- Received SRXPROXY_SIGTRA_GENERATION_REQUEST ---\n");
    printf("Signature ID:    %u (0x%08x)\n", signature_id, signature_id);
    printf("Prefix Length:   %u\n", prefixLen);
    printf("Prefix:          %u.%u.%u.%u (raw: 0x%08x)\n",
          (prefix >> 24) & 0xFF, (prefix >> 16) & 0xFF,
          (prefix >> 8) & 0xFF, prefix & 0xFF, prefix);

    printf("AS Path Length:  %u\n", as_path_len);
    for (int i = 0; i < as_path_len && i < 16; i++) {
        printf("  AS Path[%d]:      %u\n", i, as_path[i]);
    }
    printf("Raw Timestamp:   %u\n", ntohl(timestamp));
    printf("OTC Field:       %u\n", otcField);
    printf("Origin AS:       %u\n", originAS);
    printf("Peer Count:      %u\n", peer_count);
    for (int i = 0; i < peer_count && i < 16; i++) {
        printf("  Peer[%d]:        %u\n", i, peers[i]);
    }
    printf("Requesting ASN:  %u\n", requestingASN);
    printf("Block Count:     %u\n", blocks_count);
    printf("---------------------------------------------------\n\n");
    
    printf("Client Router ID: %u\n", client->routerID);
    // Load SKI 
    char* skiStr = self->proxyMap[client->routerID].bgpsecKey;
    uint8_t ski[20];    
    if (parseHexSKI(skiStr, ski) == 0) {
        printf("Parsed SKI:\n");
        for (int i = 0; i < 20; ++i) {
            printf("%02X ", ski[i]);
        }
        printf("\n");
    }
    
    uint8_t finalHash[SHA256_DIGEST_LENGTH];
    uint8_t blockHash[SHA256_DIGEST_LENGTH];

    // Step 1: Calculate the initial hash
    // Initial Hash = Hash(Origin || Prefix || PrefixLen || OTCField) 
    uint8_t initialHash[SHA256_DIGEST_LENGTH];
    uint8_t initialInput[sizeof(uint32_t) * 4 + sizeof(uint8_t)];
    size_t offset = 0;
    if (as_path_len > 0) {
      for (int i = 0; i < as_path_len && i < 16; i++) {
        memcpy(initialInput + offset, &as_path[i], sizeof(uint32_t)); offset += sizeof(uint32_t);
      }
    }
    memcpy(initialInput + offset, &requestingASN, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(initialInput + offset, &prefix, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(initialInput + offset, &prefixLen, sizeof(uint8_t)); offset += sizeof(uint8_t);
    memcpy(initialInput + offset, &otcField, sizeof(uint32_t)); offset += sizeof(uint32_t);
    SHA256(initialInput, offset, initialHash);

    if (blocks_count != 0) {
      // Hash over all previous blocks
      uint8_t* raw = (uint8_t*)generation_request;
      SRXPROXY_SIGTRA_BLOCK* blocks = (SRXPROXY_SIGTRA_BLOCK*)(raw + sizeof(SRXPROXY_SIGTRA_GENERATION_REQUEST));
      size_t blocksLength = blocks_count * sizeof(SRXPROXY_SIGTRA_BLOCK);
      SHA256((uint8_t*)blocks, blocksLength, blockHash);

      // Combine the initial hash and the block hash
      uint8_t combined[SHA256_DIGEST_LENGTH * 2];
      memcpy(combined, initialHash, SHA256_DIGEST_LENGTH);
      memcpy(combined + SHA256_DIGEST_LENGTH, blockHash, SHA256_DIGEST_LENGTH);
      SHA256(combined, sizeof(combined), finalHash);
    } else {
      // Copy the initial hash to finalHash for later use
      memcpy(finalHash, initialHash, SHA256_DIGEST_LENGTH);
    }

    // Iterate over peers and create blocks
    for (uint8_t i = 0; i < peer_count && i < 16; i++)  {
      uint8_t input[SHA256_DIGEST_LENGTH + sizeof(uint32_t) * 3 + 20];
      size_t pos = 0;
      memcpy(input + pos, finalHash, SHA256_DIGEST_LENGTH); pos += SHA256_DIGEST_LENGTH;
      memcpy(input + pos, &timestamp, sizeof(uint32_t)); pos += sizeof(uint32_t);
      memcpy(input + pos, ski, 20); pos += 20;
      memcpy(input + pos, &peers[i], sizeof(uint32_t)); pos += sizeof(uint32_t);
      uint8_t hash[SHA256_DIGEST_LENGTH];
      SHA256(input, pos, hash);
      printf("\nFinal Hash for Peer %u: ", peers[i]);
      for (size_t j = 0; j < SHA256_DIGEST_LENGTH; j++) {
          printf("%02x", hash[j]);
      }
      printf("\n");
    }

    // Done with hash calculation, now sign the message
    // Load EC_KEY from PEM
    const char* keyfile = "/home/nils/Dokumente/ASPA+/NIST-BGP-SRx/examples/bgpsec-keys/raw-keys/65000.pem";
    FILE* fp = fopen(keyfile, "r");
    if (!fp) {
        perror("Failed to open key file");
        return 1;
    }
    printf("Opened Key file");
    EC_KEY* key = load_ec_key_from_file(keyfile);
    uint8_t signature[72];     
    unsigned int signature_len = 0;
    if (!ECDSA_sign(0, finalHash, SHA256_DIGEST_LENGTH, signature, &signature_len, key)) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    printf("Signature created! Len: %u bytes\n", signature_len);
    

    sendSigtraGeneration(svrSock, client, false, signature_id, signature, signature_len);

    EC_KEY_free(key);
    printf("Done with Key free\n");
    printf("Sending signature back to client...\n");
    return retVal; 
  }



/**
 * This method processes the validation result request. This method is called by
 * the packet handler and if necessary the request will be added to the command
 * queue. This method does NOT send error packets to the proxy!
 *
 * @param self The server connection handler.
 * @param svrSock The server socket used to send a possible validation request
 *                receipt
 * @param client The client instance where the packet was received on
 * @param updateCache The instance of the update cache
 * @param hdr The signature request header
 *
 * @return false if an internal (fatal) error occurred, otherwise true.
 */
static bool processSignatureRequest(ServerConnectionHandler* self,
                                    ServerSocket* svrSock, ServerClient* client,
                                    SRxUpdateID updateID,
                                    SRXPROXY_SIGN_REQUEST* hdr)
{
  LOG(LEVEL_DEBUG, HDR "Enter processSignatureRequest", pthread_self());
  UpdSigResult* signResult = malloc(sizeof(UpdSigResult));
  bool complete = (hdr->blockType & SRX_PROXY_BLOCK_TYPE_LATEST_SIGNATURE) == 0;

  bool retVal = true;

  signResult = getUpdateSignature(self->updateCache, signResult,
                                  &updateID, ntohl(hdr->prependCounter),
                                  ntohl(hdr->peerAS),
                                  ntohs(hdr->algorithm), complete);

  if (signResult->containsError)
  {
    sendError(signResult->errorCode, svrSock, client, false);
    // If the error was that the update could not be located send a sync request
    // to synchronize the server and client.
    if (signResult->errorCode == SRXERR_UPDATE_NOT_FOUND)
    {
      retVal = sendSynchRequest(svrSock, client, false);
    }
  }
  //No error - Check if data is available that can be send right away
  else if (signResult->signatureBlock != NULL)
  {
    if (!sendSignatureNotification(svrSock, client, updateID,
                                   signResult->signatureLength,
                                   signResult->signatureBlock, false))
    {

      retVal = false;
    }
  }
  else // No data was available, add request to command handler for signing
  {
    if (!queueCommand(self->cmdQueue, COMMAND_TYPE_SRX_PROXY, svrSock, client,
                                      updateID, ntohl(hdr->length),
                                      (uint8_t*)hdr))
    {
      RAISE_ERROR("Could not add validation request to command queue!");
      retVal = false;
    }
  }
  free(signResult);

  LOG(LEVEL_DEBUG, HDR "Exit processSignatureRequest", pthread_self());
  return retVal;
}

/**
 * SRx receives a packet from one of the proxy clients. This method is called
 * before the command handler will see the request. This will be decided in this
 * method. In case a receipt is requested this method will generate the update
 * identifier and query the update cache, if the update has already a result.
 *
 * In case a result is found, the result is taken and will be send back to the
 * proxy together with the update ID.
 *
 * In case the update is never be seen before the default values will be
 * returned and the update validation request will be added to the command
 * queue for further processing.
 *
 * @param svrSock The server socket
 * @param client  The client thread where the packet was received on
 * @param packet  The packet itself
 * @param length  length The length of the packet received
 * @param srvConHandler The pointer to the sever connection handler.
 */
void _handlePacket(ServerSocket* svrSock, ServerClient* client,
                         void* packet, PacketLength length,
                         void* srvConHandler)
{
  LOG(LEVEL_DEBUG, HDR "Enter handlePacket", pthread_self());
  // print raw packet data for debugging
  hexDump(packet, length);
  // Check if the packet is valid and has the minimum required length
  // convert hex string to binary string


  ServerConnectionHandler* self  = (ServerConnectionHandler*)srvConHandler;
  SRXPROXY_BasicHeader*    bhdr  = NULL;
  SRXPROXY_SIGN_REQUEST*   srHdr  = NULL;
  SRXPROXY_DELETE_UPDATE*  duHdr = NULL;
  // By default the data id is zero except for packets where the updateID is
  // provided such as signature request and delete requests.
  uint32_t dataID = 0;

  // Check if the client is already initialized - What this means is check if
  // we got a valid client ID. This MUST have happened prior the arrival of any
  // of the following packets.
  ClientThread* clientThread = (ClientThread*)client;

  bool addToQueue = false;

  // No data?
  if (length < sizeof(SRXPROXY_BasicHeader))
  {
    RAISE_ERROR("The packet given with %u bytes does not have the minimum "
                "required length of %u bytes!", length,
                sizeof(SRXPROXY_BasicHeader));
  }
  else
  {
    bhdr = (SRXPROXY_BasicHeader*)packet;
    switch (bhdr->type)
    {
      case PDU_SRXPROXY_VERIFY_V4_REQUEST:
      case PDU_SRXPROXY_VERIFY_V6_REQUEST:
        if (!clientThread->initialized)
        {
          // A handshake was not performed, otherwise the clientThread would be
          // initialized!!!
          RAISE_SYS_ERROR("Connection not initialized yet - "
                          "Handshake missing!!!");
          sendError(SRXERR_INTERNAL_ERROR, svrSock, client, false);
          sendGoodbye(svrSock, client, false);
          //TODO: Also close the socket and remove the thread
          // - it might be closed in goodbye though
        }
        else
        {
          LOG(LEVEL_DEBUG, HDR "Received Validation Request from proxy[0x%08X],"
                          " type=%u", pthread_self(), clientThread, bhdr->type);
          // the following method will add the command to the queue if
          // necessary therefore keep it false here so it won't be added twice.
          // This is done because within this process SRx calculates already the
          // UpdateID and adds it to the command item.
          if (!processValidationRequest(self, svrSock, clientThread,
                                   (SRXRPOXY_BasicHeader_VerifyRequest*)packet))
          {
            sendError(SRXERR_INTERNAL_ERROR, svrSock, client, false);
            sendGoodbye(svrSock, client, false);
            //TODO: Also close the socket and remove the thread
            // - it might be closed in goodbye though
          }
        }
//#endif
        break;
      case PDU_SRXPROXY_REGISTER_SKI:
        if (!clientThread->initialized)
        {
          // A handshake was not performed, otherwise the clientThread would be
          // initialized!!!
          RAISE_SYS_ERROR("Connection not initialized yet - "
                          "Handshake missing!!!");
          sendError(SRXERR_INTERNAL_ERROR, svrSock, client, false);
          sendGoodbye(svrSock, client, false);
          //TODO: Also close the socket and remove the thread
          // - it might be closed in goodbye though
        }
        else
        {

          // self->proxyMap[clientID].socket     = cSocket;
          // the following method will add the command to the queue if
          // necessary
          // TODO implement
        }
      break;
      case PDU_SRXPROXY_SIGTRA_VALIDATION_REQUEST:
        LOG(LEVEL_INFO,  "Received PDU_SRXPROXY_SIGTRA__VALIDATION_REQUEST");
        SRXPROXY_SIGTRA_VALIDATION_REQUEST* valReq = (SRXPROXY_SIGTRA_VALIDATION_REQUEST*)packet;
        bool val_result = processSigtraValidationRequest(self, svrSock, client, valReq);
        printf("Validation result: %d\n", val_result);
        if(!sendSigtraResult(svrSock, client, val_result, false, 0)){
          RAISE_ERROR("Failed to send SRXPROXY_SIGTRA_VALIDATION_RESPONSE");
          sendError(SRXERR_INTERNAL_ERROR, svrSock, client, false);
          sendGoodbye(svrSock, client, false);
        }
        break;
      case PDU_SRXPROXY_SIGTRA_GENERATION_REQUEST:
        LOG(LEVEL_INFO,  "Received PDU_SRXPROXY_SIGTRA_GENERATION_REQUEST");
        SRXPROXY_SIGTRA_GENERATION_REQUEST* genReq = (SRXPROXY_SIGTRA_GENERATION_REQUEST*)packet;
        bool gen_result = processSigtraGenerationRequest(self, svrSock, client, genReq);
        break;  
      case PDU_SRXPROXY_SIGN_REQUEST:
        if (!clientThread->initialized)
        {
          // A handshake was not performed, otherwise the clientThread would be
          // initialized!!!
          RAISE_SYS_ERROR("Connection not initialized yet - "
                          "Handshake missing!!!");
          sendError(SRXERR_INTERNAL_ERROR, svrSock, client, false);
          sendGoodbye(svrSock, client, false);
          //TODO: Also close the socket and remove the thread
          // - it might be closed in goodbye though
        }
        else
        {
          // the following method will add the command to the queue if
          // necessary
          srHdr = (SRXPROXY_SIGN_REQUEST*)packet;
          LOG(LEVEL_DEBUG, HDR "Received signature request fore update [0x%08X]",
                           pthread_self(), ntohl(srHdr->updateIdentifier));
          if (!processSignatureRequest(self, svrSock, client,
                                       ntohl(srHdr->updateIdentifier), srHdr))
          {
            sendError(SRXERR_INTERNAL_ERROR, svrSock, client, false);
            sendGoodbye(svrSock, client, false);
            //TODO: Also close the socket and remove the thread
            // - it might be closed in goodbye though
          }
        }
        break;
      case PDU_SRXPROXY_DELTE_UPDATE:
        if (!clientThread->initialized)
        {
          // A handshake was not performed, otherwise the clientThread would be
          // initialized!!!
          RAISE_SYS_ERROR("Connection not initialized yet - "
                          "Handshake missing!!!");
          sendError(SRXERR_INTERNAL_ERROR, svrSock, client, false);
          sendGoodbye(svrSock, client, false);
          //TODO: Also close the socket and remove the thread
          // - it might be closed in goodbye though
        }
        else
        {
          // the following method will add the command to the queue. No
          // pre-processing necessary
          duHdr = (SRXPROXY_DELETE_UPDATE*)packet;
          dataID = ntohl(duHdr->updateIdentifier);
          LOG(LEVEL_DEBUG, HDR "Received deletion request fore update [0x%08X]",
                           pthread_self(), dataID);
          addToQueue = true;
        }
        break;
      case PDU_SRXPROXY_HELLO:
        if (!clientThread->active || clientThread->initialized)
        {
          // A hello packet is received at an inactive socket or an already
          // initialized socket.
          // Send Error and close connection.
          LOG(LEVEL_WARNING, HDR "Received unexpected a Hello packet from "
                             "proxy [0x%08X], client [0x%02X]",
                             clientThread->proxyID, clientThread->routerID);
          sendError(SRXERR_INVALID_PACKET, svrSock, client, false);
          sendGoodbye(svrSock, client, false);
          //TODO: Also close the socket and remove the thread
          // - it might be closed in goodbye though
          break;
        }
      case PDU_SRXPROXY_GOODBYE:
        // Just prepare for the ordered disconnect
        if (clientThread->active && clientThread->initialized)
        {
          if (clientThread->goodByeReceived)
          {
            LOG(LEVEL_NOTICE, "Recived a goodbye message at least a second "
              "time. Proxy [0x%08X]", clientThread->proxyID);
          }
          clientThread->goodByeReceived = true;
        }

      // else continue with the default behavior
      default:
        if (bhdr->type <= PDU_SRXPROXY_UNKNOWN)
        {
          // This deals with peer changes, update deletes, etc.
          addToQueue = true;
        }
        else
        {
          RAISE_ERROR("Invalid srx pdu [\'%u\'] received", bhdr->type);
          sendError(SRXERR_INVALID_PACKET, svrSock, client, false);
          sendGoodbye(svrSock, client, false);
          //TODO: Also close the socket and remove the thread
          // - it might be closed in goodbye though
        }
    }

    // Add to command queue if a valid type and necessary
    if (addToQueue)
    {
      // Whatever SRX packet except validation and signature request. It will
      // be added to the command queue for further processing.
      queueCommand(self->cmdQueue, COMMAND_TYPE_SRX_PROXY, svrSock, client,
                   dataID, length, (uint8_t*)packet);
    }
  }
  LOG(LEVEL_DEBUG, HDR "Exit handlePacket", pthread_self());
}

/**
 * SRx receives a packet from one of the proxy clients. This method is called
 * before the command handler will see the request. This will be decided in this
 * method. In case a receipt is requested this method will generate the update
 * identifier and query the update cache, if the update has already a result.
 *
 * In case a result is found, the result is taken and will be send back to the
 * proxy together with the update ID.
 *
 * In case the update is never be seen before the default values will be
 * returned and the update validation request will be added to the command
 * queue for further processing.
 *
 * @param svrSock The server socket
 * @param client  The client thread where the packet was received on
 * @param packet  The packet itself
 * @param length  length The length of the packet received
 * @param srvConHandler The pointer to the sever connection handler.
 */
void handlePacket(ServerSocket* svrSock, ServerClient* client,
                  void* packet, PacketLength length, void* srvConHandler)
{
  // Preparation for receiver queue
  ServerConnectionHandler* handler = (ServerConnectionHandler*)srvConHandler;
  SCH_ReceiverQueue* queue = (SCH_ReceiverQueue*)handler->receiverQueue;
  LOG(LEVEL_DEBUG, HDR "Enter regular handle packet");
  if (queue == NULL)
  {
    LOG(LEVEL_DEBUG, HDR "Enter regular handle packet -> if ");
    _handlePacket(svrSock, client, packet, length, srvConHandler);
  }
  else
  {
    LOG(LEVEL_DEBUG, HDR "Enter regular handle packet -> else ");
    addToSCHReceiverQueue(packet, svrSock, client, length, queue);
  }
}

/**
 * This method is called as soon as a TCP connection is established to the
 * SRx client proxy.
 *
 * @param svrSock The server socket the connection was accepted on.
 * @param client The thread that deals with this connection or NULL if the
 *               connection is a multi user connection. (later one is currently
 *               not supported!)
 * @param fd The file descriptor if the client socket/
 * @param connected If the session is connected.
 * @param user The server connection handler itself.
 *
 * @return false in case an error occurred.
 */
static bool handleStatusChange(ServerSocket* svrSock, ServerClient* client,
                               int fd, bool connected, void* serverConnHandler)
{
 // LOG(LEVEL_DEBUG, HDR "Enter handleStatusChange", pthread_self());
  ServerConnectionHandler* self = (ServerConnectionHandler*)serverConnHandler;

  // ServerClient is a place holder similar to void, therefore a typecast is
  // necessary
  ClientThread* clientThread = (ClientThread*)client;
  bool retVal = true;

  // A new client arrived
  if (connected)
  {
    // Add the new client to the client list.
    if (!appendDataToSList(&self->clients, client))
    {
      RAISE_SYS_ERROR("Not enough memory to handle the new connection!");
      retVal = false;
    }
  }
  else
  {
    if (!self->inShutdown)
    {
      LOG(LEVEL_NOTICE, "Lost a connection to proxy [0x%08X]. Remove mapping "
          "from client list!", self->proxyMap[clientThread->routerID].proxyID);
    }

    deleteFromSList(&self->clients, client);

    bool crashed = !(self->inShutdown || clientThread->goodByeReceived);
    deactivateConnectionMapping(self, clientThread->routerID, crashed,
                                self->sysConfig->defaultKeepWindow);

    deleteFromSList(&svrSock->cthreads, client);
  }
  LOG(LEVEL_DEBUG, HDR "Exit handleStatusChange (%s)", pthread_self(),
                   retVal ? "true" : "false");
  return retVal;
}

/**
 * Provides the server loop that waits for all client requests processes them.
 *
 * @note Blocking-call!
 *
 * @param self The server connection handler.
 * @param cmdQueue Existing Command Queue
 * @see stopProcessingRequests
 */
void startProcessingRequests(ServerConnectionHandler* self,
                             CommandQueue* cmdQueue)
{
  LOG(LEVEL_DEBUG, HDR "Enter startProcessingRequests", pthread_self());
  self->cmdQueue = cmdQueue;
  runServerLoop(&self->svrSock, MODE_SINGLE_CLIENT, handlePacket,
                handleStatusChange, self);
  LOG(LEVEL_DEBUG, HDR "Exit startProcessingRequests", pthread_self());
}

/**
 * Stops processing client requests.
 * Closes all client connections and the server-socket.
 *
 * @param self The server connection handler.
 */
void stopProcessingRequests(ServerConnectionHandler* self)
{
  LOG(LEVEL_DEBUG, HDR "Enter stopProcessingRequests", pthread_self());
  SCH_ReceiverQueue* receiverQueue = (SCH_ReceiverQueue*)self->receiverQueue;
  stopSCHReceiverQueue(receiverQueue);
  stopServerLoop(&self->svrSock);
  LOG(LEVEL_DEBUG, HDR "Exit stopProcessingRequests", pthread_self());
}

/**
 * Sends a packet to all connected clients.
 *
 * @param self The server connection handler.
 * @param packet Data-stream
 * @param length Length of \c packet in Bytes
 * @return \c true = sent, \c false = failed
 */
bool broadcastPacket(ServerConnectionHandler* self,
                     void* packet, PacketLength length)
{
  LOG(LEVEL_DEBUG, HDR "Enter broadcastPacket", pthread_self());
  bool retVal = true;
  if (sizeOfSList(&self->clients) > 0)
  {
    SListNode*    cnode;
    ServerClient* clientPtr;

    FOREACH_SLIST(&self->clients, cnode)
    {
      clientPtr = (ServerClient*)getDataOfSListNode(cnode);
      if (clientPtr != NULL)
      {
        if (!sendPacketToClient(&self->svrSock, clientPtr,
                                packet, (size_t)length))
        {
          LOG(LEVEL_DEBUG, HDR "Could not send the packet to the client",
                           pthread_self());
          retVal = false;
          break;
        }
      }
    }
  }
  LOG(LEVEL_DEBUG, HDR "Exit broadcastPacket", pthread_self());

  return true;
}

/**
 * Allows to pre-configure the proxy Map. This function performs all mappings
 * or none. A mapping fails if it is already made.
 *
 * @param self The server connection handler.
 * @param mappings A mapping array of 256 elements
 *
 * @return true if the mappings could be performed, otherwise false. In the
 *              later case as many mappings are performed as possible.
 *
 * @since 0.3
 */
bool configureProxyMap(ServerConnectionHandler* self, uint32_t* mappings)
{
  bool addedAllToMap = true; // added all entries to map
  int idx;

  // check for each provided mapping and add it if possible. This takes care of
  // duplicate configurations as well.
  for (idx = 0; idx < MAX_PROXY_CLIENT_ELEMENTS; idx++)
  {
    // Go through the array and read the configured mappings
    if (mappings[idx] > 0)
    {
      // activate is false and configured true when passing false while adding
      if (!addMapping(self, mappings[idx], idx, NULL, false))
      {
        RAISE_ERROR("Mapping [pid:0x%08X] <=> [cid:0x%02X] failed!",
                    mappings[idx], idx);
        addedAllToMap = false;
      }
    }
  }

  return addedAllToMap;
}

/**
 * Search for the internal clientID if the provided proxy ID. This will return
 * either a recently used / pre configured clientID or 0.
 *
 * @param self The Server connection handler.
 * @param proxyID The proxy whose mapping is requested.
 *
 * @return The id of the proxyClient or zero "0".
 *
 * @since 0.3.0
 */
uint8_t findClientID(ServerConnectionHandler* self, uint32_t proxyID)
{
  int noMappings = self->noMappings;
  int clientID = 0;

  int index = 1; // first element must not be used!!

  if (proxyID == 0)
  {
    RAISE_ERROR ("A proxyID other than zero is required!");
  }
  else
  {
    // Go through the list of clients until one is found that matches the proxy
    // id or no further clients are registered!
    while ((index < MAX_PROXY_CLIENT_ELEMENTS) && (noMappings > 0))
    {
      if (self->proxyMap[index].proxyID > 0)
      {
        noMappings--;
        if (self->proxyMap[index].proxyID == proxyID)
        {
          // Found element
          clientID = index;
          noMappings = 0;
        }
      }
      index++;
    }
  }

  return clientID;
}

/**
 * Create a new client ID and return it.
 *
 * @param self The ClienttConnectionHandler instance.
 *
 * @return The newly generated clientID or zero "0" if no more are available
 *
 * @since 0.3.0
 */
uint8_t createClientID(ServerConnectionHandler* self)
{
  uint8_t clientID = 0;
  int index = 1;
  while ((index < MAX_PROXY_CLIENT_ELEMENTS) && (clientID == 0))
  {
    if (self->proxyMap[index].proxyID == 0)
    {
      // This will end the loop
      clientID = index;
    }
    index++;
  }

  return clientID;
}

/**
 * Attempt to add the provided Mapping. The mapping will fail if either of
 * the provided entries is actively mapped already. Adding a mapping does not
 * alter the attribute "predefined".
 *
 * @param self The server connection handler.
 * @param proxyID array containing "mappings" number of proxy ID's
 * @param clientID array containing "mappings" number of client ID's
 * @param cSocket The client socket, can be NULL.
 * @param activate indicates if the mapping will be immediately activated.
 *        This should not be done for predefining mappings. If activate is false
 *        the mapping will be considered pre-configured by default
 *
 * @return true if the mapping could be performed.
 *
 * @since 0.3
 */
bool addMapping(ServerConnectionHandler* self, uint32_t proxyID,
                uint8_t clientID, void* cSocket, bool activate)
{
  // Assume it is not OK
  bool ok = false;

  // first check if a mapping for the proxyID already exist
  uint8_t registeredClientID = findClientID(self, proxyID);

  if (registeredClientID == 0)
  {
    // The proxy is not registered yet, check a client registration
    if (self->proxyMap[clientID].proxyID == 0)
    {
      if (!self->proxyMap[clientID].isActive)
      {
        ok = true;
      }
      else
      { // Should never occur
        RAISE_SYS_ERROR("EM1: Internal Mapping Error, found active 0-0 "
                        "mapping");
      }
    }
    else if (self->proxyMap[clientID].proxyID == proxyID)
    {
        RAISE_SYS_ERROR("EM2: Internal Mapping Error, A mapping exists but"
                        "could not be detected by findClientID!!");
    }
    else
    {
      LOG(LEVEL_ERROR, "EM3: Attempt to map proxy[0x%08X] to client[0x%02X] "
                       "that is already mapped to proxy[0x%08X].", proxyID,
                       clientID, self->proxyMap[clientID].proxyID);
    }
  }
  else if (registeredClientID == clientID)
  {
    // It might be a pre-configured mapping. or inactive mapping.
    if (!self->proxyMap[clientID].isActive)
    {
      ok = true;
    }
    else
    {
      // The mapping is active, it might be that the mapping was called twice
      if (self->proxyMap[clientID].socket == cSocket)
      {
        ok = true;
        LOG(LEVEL_NOTICE, "Attempt to re-register an already registered "
                          "mapping. Socket is the same => Check program flow, "
                          "it might not be optimal!");
      }
      else
      {
        // either misconfiguration of a proxy or a proxy reboot was unnoticed.
        // reboots / disconnects of proxies require to deactivate the mapping.
        LOG(LEVEL_ERROR, "EM4: Attempt to re-register an already registered "
                         "mapping. Socket is different. This might indicate "
                         "a configuration failure of a proxy or the proxy "
                         "rebooted without the server noticing it.");
      }
    }
  }
  else // proxy is registered to a different client
  {
    LOG(LEVEL_ERROR, "EM5: Attempt to re-register an already registered "
                     "proxy. This might indicate a configuration failure of "
                     "a proxy or the proxy rebooted without the server "
                     "noticing it.");
  }

  // Now if still ok, get the map element belonging to the clientID
  if (ok)
  {
  
#ifdef USE_GRPC
    ClientThread* cthread = (ClientThread*)cSocket;
#endif // USE_GRPC
    LOG(LEVEL_INFO,"Register proxyID[0x%08X] as clientID[0x%08X]",
        proxyID, clientID);
    if (self->proxyMap[clientID].proxyID == 0)
    {
      // Increase the number of mappings only if the proxyID == 0, otherwise
      // it is a previous mapping that gets reconfigured / (re)activated
      self->noMappings++;
      self->proxyMap[clientID].proxyID    = proxyID;
    }
    // 
    self->proxyMap[clientID].socket     = cSocket;
    self->proxyMap[clientID].isActive   = activate;
    self->proxyMap[clientID].crashed    = 0;
#ifdef USE_GRPC
    if(cthread && cthread->type_grpc_client)
    {
      self->proxyMap[clientID].grpcClient = true;
    }
#endif
    if (!activate)
    {
      // The mapping gets added. if not active is is considered pre-configured.
      // If it is configured and active the configuration flag must be set
      // outside.
      self->proxyMap[clientID].preDefined = true;
    }
  }

  return ok;
}

/**
 * Set the activation flag for the given client. This method returns true only
 * if a mapping for this client exist. This method only manipulates the internal
 * flag but does not alter the connectivity in any way.
 *
 * @param self The ServerConnectionhandler instance
 * @param clientID The client id
 * @param value The new value of the active flag
 *
 * @return true if a mapping exists.
 *
 * @since 0.3.0
 */
bool setActivationFlag(ServerConnectionHandler* self, uint8_t clientID,
                        bool value)
{
  bool retVal = false;
  if (clientID > 0)
  {
    if (self->proxyMap[clientID].proxyID > 0)
    {
      self->proxyMap[clientID].isActive = value;
      retVal = true;
    }
  }

  return retVal;
}


/**
 * Attempts to delete an existing mapping. This method requires an inactive
 * mapping. If the mapping is pre-defined, only the socket will be NULL'ed
 *
 * @param self The server connection handler
 * @param clientID the client ID whose mapping has to be removed
 * @param keepWindow the keepWindow that shows how long updates are requested
 *                    to be kept in the system.
 *
 * @return true if the mapping could be deleted.
 *
 * @since 0.3.0
 */
bool _delMapping(ServerConnectionHandler* self, uint8_t clientID,
                 uint16_t keepWindow)
{
  bool retVal = false;
  if (!self->proxyMap[clientID].isActive)
  {
    // remove update associate if needed
    if (self->proxyMap[clientID].updateCount > 0)
    {
      // TODO: Use the requested keepWindow - not yet added to this method.
      unregisterClientID(self->updateCache, clientID, &self->proxyMap[clientID],
                         keepWindow);
    }

    if (    !self->proxyMap[clientID].preDefined
         && (self->proxyMap[clientID].crashed == 0))
    {
      // delete and reset this mapping, it is not expected to come back.
      self->proxyMap[clientID].proxyID = 0;
      self->proxyMap[clientID].preDefined = false;
    }
    self->proxyMap[clientID].socket = NULL;

    retVal = true;
  }

  return retVal;
}

/**
 * Mark the this connection as closed. In case the connection closed without a
 * crash and it was NOT pre-configured, it attempts to delete an existing
 * mapping. This method requires an inactive mapping.  If the mapping is
 * pre-defined, only the socket will be NULL'ed.
*
 * @param self The ServerConnectionhandler instance
 * @param clientID The client id
 * @param crashed indicator if the connection crashed
 * @param keepWindow Indicates how long the update should remain in the system
 *                   before the garbage collector removes it.
 *
 * @since 0.3.0
 * @see delMapping
 */
void deactivateConnectionMapping(ServerConnectionHandler* self,
                                 uint8_t clientID, bool crashed,
                                 uint16_t keepWindow)
{
  struct timespec time;
  clock_gettime(CLOCK_REALTIME, &time);
  if (keepWindow < (uint16_t)self->sysConfig->defaultKeepWindow)
  {
    // Don't use less than the servers configured keepWindow
    keepWindow = (uint16_t)self->sysConfig->defaultKeepWindow;
  }

  self->proxyMap[clientID].isActive = false;
  self->proxyMap[clientID].crashed = crashed ? time.tv_sec : 0;
  _delMapping(self, clientID, keepWindow);
  self->proxyMap[clientID].updateCount = 0;
#ifdef USE_GRPC
  self->proxyMap[clientID].grpcClient = false;
#endif
}

/**
 * Set the shutdown flag.
 *
 * @param self The connection handler instance
 *
 * @since 0.3.0
 */
void markConnectionHandlerShutdown(ServerConnectionHandler* self)
{
  self->inShutdown = true;
}


